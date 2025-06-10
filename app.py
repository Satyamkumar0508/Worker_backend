from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from typing import List, Optional
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import MongoClient
import jwt
import random
import string
from pydantic import BaseModel, Field, EmailStr
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import ssl
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Village Jobs API", debug=True)

# Configure CORS with more permissive settings for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add middleware to log all requests
@app.middleware("http")
async def log_requests(request, call_next):
    logger.info(f"🚀 Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"✅ Response: {response.status_code}")
    return response

# MongoDB connection with error handling
try:
    MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://workers-globe:satya@cluster0.qgsk7in.mongodb.net/")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # Test the connection
    client.admin.command('ping')
    logger.info("✅ Successfully connected to MongoDB")
    db = client["village_jobs"]
except Exception as e:
    logger.error(f"❌ Failed to connect to MongoDB: {e}")
    raise Exception("Database connection failed")

# Collections
users_collection = db["users"]
jobs_collection = db["jobs"]
applications_collection = db["applications"]
notifications_collection = db["notifications"]
payments_collection = db["payments"]
otp_collection = db["otps"]

# Email configuration - Updated for production email sending
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "workersglobe.noreply@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")  # App password for Gmail
EMAIL_FROM_NAME = "Workers Globe"

# Environment settings
ENVIRONMENT = os.getenv("ENVIRONMENT", "production")  # Changed default to production
ENABLE_EMAIL_SENDING = os.getenv("ENABLE_EMAIL_SENDING", "true").lower() == "true"

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "12d255a21514fdbdac73601172ae5ceb3183888f9b8aec35f35fcd88815e8363")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="verify-otp")

# Helper function to convert ObjectId to string
def serialize_id(obj):
    if "_id" in obj:
        obj["id"] = str(obj["_id"])
        del obj["_id"]
    return obj

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserBase(BaseModel):
    name: str
    email: EmailStr
    gender: str
    age: int
    permanentAddress: str
    presentAddress: str
    workingCity: str
    pincode: str
    userType: str
    phone: str
    bio: str
    skills: Optional[List[str]] = []
    rating: float = 0.0
    yearsOfExperience: Optional[int] = 0
    photo: Optional[str] = None
    idProof: Optional[str] = None

class UserCreate(UserBase):
    pass

class UserResponse(UserBase):
    id: str
    createdAt: datetime

class JobBase(BaseModel):
    title: str
    description: str
    location: str
    category: Optional[str] = None  # Made optional since it's now derived from title
    requiredSkills: List[str] = []  # Made optional with default
    payment: str
    duration: str
    wageType: Optional[str] = "daily"  # daily/weekly/monthly/total
    negotiable: bool = False
    preferredExperience: Optional[int] = None
    preferredAge: Optional[str] = None  # "18-25", "26-35", etc.
    preferredGender: Optional[str] = None  # "male", "female", "any"
    jobStatus: str = "OPEN"  # OPEN/CLOSED

class JobCreate(JobBase):
    pass

class JobResponse(JobBase):
    id: str
    providerId: str
    providerName: str
    status: str = "open"
    createdAt: datetime
    applicants: int = 0
    assignedTo: Optional[str] = None
    completedAt: Optional[datetime] = None
    matchScore: Optional[float] = None  # For job matching

class ApplicationBase(BaseModel):
    jobId: str
    seekerId: str
    seekerName: str

class ApplicationCreate(ApplicationBase):
    pass

class ApplicationResponse(ApplicationBase):
    id: str
    status: str = "pending"
    appliedAt: datetime
    seekerProfile: dict
    feedback: Optional[dict] = None
    rankingScore: Optional[float] = None

class NotificationBase(BaseModel):
    userId: str
    type: str
    title: str
    message: str

class NotificationCreate(NotificationBase):
    pass

class NotificationResponse(NotificationBase):
    id: str
    read: bool = False
    timestamp: datetime

class PaymentBase(BaseModel):
    jobId: str
    providerId: str
    plan: str
    amount: float

class PaymentCreate(PaymentBase):
    pass

class PaymentResponse(PaymentBase):
    id: str
    status: str = "completed"
    createdAt: datetime

class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerification(BaseModel):
    email: EmailStr
    otp: str

class JobCompletionRequest(BaseModel):
    rating: int
    feedback: str

# Authentication functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except jwt.PyJWTError:
        raise credentials_exception
    user = users_collection.find_one({"email": token_data.email})
    if user is None:
        raise credentials_exception
    return serialize_id(user)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_email(to_email: str, subject: str, body: str):
    """Enhanced email sending function with actual email delivery"""
    try:
        logger.info(f"📧 Attempting to send email to {to_email}")
        logger.info(f"📧 Subject: {subject}")
        
        # Check if email sending is enabled
        if not ENABLE_EMAIL_SENDING:
            logger.info(f"📧 [DISABLED] Email sending is disabled. Email would be sent to {to_email}")
            return True
        
        # Check if we have email credentials
        if not EMAIL_USER or not EMAIL_PASSWORD:
            logger.error("❌ Email credentials not configured. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.")
            return False
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{EMAIL_FROM_NAME} <{EMAIL_USER}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Attach HTML body
        html_part = MIMEText(body, 'html')
        msg.attach(html_part)
        
        # Create secure SSL context
        context = ssl.create_default_context()
        
        # Connect to server and send email
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.ehlo()  # Can be omitted
            server.starttls(context=context)
            server.ehlo()  # Can be omitted
            
            # Login to server
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            logger.info(f"✅ Successfully logged in to SMTP server")
            
            # Send email
            text = msg.as_string()
            server.sendmail(EMAIL_USER, to_email, text)
            logger.info(f"📧 ✅ Email sent successfully to {to_email}")
        
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"❌ SMTP Authentication failed: {e}")
        logger.error("Please check your email credentials and ensure you're using an App Password for Gmail")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"❌ Recipient refused: {e}")
        return False
    except smtplib.SMTPServerDisconnected as e:
        logger.error(f"❌ SMTP server disconnected: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Error sending email to {to_email}: {e}")
        return False

def send_welcome_email(email: str, name: str, user_type: str):
    """Send welcome email to new users"""
    subject = "Welcome to Workers Globe - Your Journey Starts Here!"
    
    # Customize content based on user type
    if user_type == "seeker":
        user_role = "Job Seeker"
        features = [
            "🔍 Browse thousands of job opportunities in your area",
            "🎯 Get matched with jobs that fit your skills and experience",
            "📱 Apply to jobs with just one click",
            "⭐ Build your reputation with ratings and reviews",
            "📧 Receive instant notifications for new job matches"
        ]
        next_steps = [
            "Complete your profile with your skills and experience",
            "Browse available jobs in your area",
            "Apply to jobs that match your interests",
            "Start building your professional reputation"
        ]
    else:  # provider
        user_role = "Job Provider"
        features = [
            "📝 Post job opportunities and find the right workers",
            "👥 Access a pool of skilled and verified workers",
            "⚡ Get applications from qualified candidates instantly",
            "⭐ Rate and review workers to help the community",
            "💼 Manage all your job postings in one place"
        ]
        next_steps = [
            "Complete your business profile",
            "Post your first job opportunity",
            "Review applications from qualified workers",
            "Build lasting relationships with reliable workers"
        ]
    
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to Workers Globe</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 30px; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 32px; font-weight: bold;">🎉 Welcome to Workers Globe!</h1>
                <p style="color: #d1fae5; margin: 15px 0 0 0; font-size: 18px;">Your trusted job platform</p>
            </div>
            
            <!-- Main Content -->
            <div style="padding: 40px 30px;">
                <!-- Personal Greeting -->
                <div style="background: #f9fafb; padding: 30px; border-radius: 12px; border-left: 4px solid #10b981; margin-bottom: 30px;">
                    <h2 style="color: #1f2937; margin-top: 0; font-size: 24px;">Hello {name}! 👋</h2>
                    <p style="color: #4b5563; font-size: 16px; line-height: 1.6; margin: 20px 0;">
                        Congratulations! Your registration as a <strong>{user_role}</strong> has been completed successfully. 
                        You're now part of the Workers Globe community - a platform that connects skilled workers with 
                        meaningful job opportunities.
                    </p>
                </div>
                
                <!-- What You Can Do -->
                <div style="margin-bottom: 30px;">
                    <h3 style="color: #1f2937; font-size: 20px; margin-bottom: 20px;">🚀 What You Can Do on Workers Globe:</h3>
                    <div style="background: #eff6ff; padding: 25px; border-radius: 10px; border-left: 4px solid #3b82f6;">
                        <ul style="color: #1e40af; font-size: 15px; line-height: 1.8; margin: 0; padding-left: 20px;">
    """
    
    for feature in features:
        body += f"<li style='margin-bottom: 8px;'>{feature}</li>"
    
    body += f"""
                        </ul>
                    </div>
                </div>
                
                <!-- Next Steps -->
                <div style="margin-bottom: 30px;">
                    <h3 style="color: #1f2937; font-size: 20px; margin-bottom: 20px;">📋 Your Next Steps:</h3>
                    <div style="background: #f0fdf4; padding: 25px; border-radius: 10px; border-left: 4px solid #10b981;">
                        <ol style="color: #166534; font-size: 15px; line-height: 1.8; margin: 0; padding-left: 20px;">
    """
    
    for step in next_steps:
        body += f"<li style='margin-bottom: 8px;'>{step}</li>"
    
    body += f"""
                        </ol>
                    </div>
                </div>
                
                <!-- Login Instructions -->
                <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 10px; padding: 20px; margin: 20px 0;">
                    <h4 style="color: #92400e; margin: 0 0 10px 0; font-size: 16px;">🔐 How to Login:</h4>
                    <p style="color: #92400e; font-size: 14px; margin: 0; line-height: 1.5;">
                        To access your account, simply visit our login page and enter your email address. 
                        We'll send you a secure verification code to complete the login process.
                    </p>
                </div>
                
                <!-- Support -->
                <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; text-align: center; margin-top: 30px;">
                    <h4 style="color: #374151; margin: 0 0 10px 0; font-size: 16px;">Need Help? We're Here for You!</h4>
                    <p style="color: #6b7280; font-size: 14px; margin: 0; line-height: 1.5;">
                        If you have any questions or need assistance getting started, our support team is ready to help. 
                        Simply reply to this email or contact us through the platform.
                    </p>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 14px; margin: 0 0 10px 0;">
                    This email was sent to {email}
                </p>
                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                    © 2024 Workers Globe. All rights reserved.
                </p>
                <div style="margin-top: 20px;">
                    <p style="color: #6b7280; font-size: 14px; margin: 0;">
                        Ready to get started? <a href="http://localhost:5173/login" style="color: #10b981; text-decoration: none; font-weight: bold;">Login to Your Account</a>
                    </p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body)

def send_otp_email(email: str, otp: str):
    subject = "Workers Globe - Login Verification Code"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Workers Globe - Login Verification</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 30px; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 32px; font-weight: bold;">Workers Globe</h1>
                <p style="color: #d1fae5; margin: 15px 0 0 0; font-size: 18px;">Your trusted job platform</p>
            </div>
            
            <!-- Main Content -->
            <div style="padding: 40px 30px;">
                <div style="background: #f9fafb; padding: 30px; border-radius: 12px; border-left: 4px solid #10b981;">
                    <h2 style="color: #1f2937; margin-top: 0; font-size: 24px;">Login Verification Code</h2>
                    <p style="color: #4b5563; font-size: 16px; line-height: 1.6; margin: 20px 0;">
                        We received a request to log in to your Workers Globe account. Please use the verification code below to complete your login:
                    </p>
                    
                    <!-- OTP Box -->
                    <div style="background: white; padding: 25px; border-radius: 10px; text-align: center; margin: 30px 0; border: 2px dashed #10b981; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="font-size: 36px; font-weight: bold; color: #10b981; letter-spacing: 8px; font-family: 'Courier New', monospace;">{otp}</div>
                    </div>
                    
                    <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 15px; margin: 20px 0;">
                        <p style="color: #dc2626; font-size: 14px; margin: 0; font-weight: 500;">
                            ⏰ This verification code will expire in 5 minutes for security purposes.
                        </p>
                    </div>
                    
                    <p style="color: #6b7280; font-size: 14px; line-height: 1.5;">
                        If you didn't request this login, please ignore this email and ensure your account is secure.
                    </p>
                </div>
                
                <!-- Security Notice -->
                <div style="margin-top: 30px; padding: 20px; background: #eff6ff; border-radius: 8px; border-left: 4px solid #3b82f6;">
                    <h3 style="color: #1e40af; margin: 0 0 10px 0; font-size: 16px;">Security Notice</h3>
                    <p style="color: #1e40af; font-size: 14px; margin: 0; line-height: 1.4;">
                        Workers Globe will never ask you to share your verification code with anyone. Keep this code confidential.
                    </p>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 14px; margin: 0 0 10px 0;">
                    This email was sent to {email}
                </p>
                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                    © 2024 Workers Globe. All rights reserved.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body)

@app.post("/register/send-otp")
async def send_registration_otp(request: OTPRequest):
    try:
        logger.info(f"📧 Registration OTP request for email: {request.email}")
        
        # Check if email already exists
        existing_user = users_collection.find_one({"email": request.email})
        if existing_user:
            logger.warning(f"⚠️ Registration OTP requested for existing email: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered. Please use login instead."
            )
        
        # Generate and store OTP with 5 minute expiry
        otp = generate_otp()
        otp_data = {
            "email": request.email,
            "otp": otp,
            "type": "registration",  # Mark as registration OTP
            "createdAt": datetime.utcnow(),
            "expiresAt": datetime.utcnow() + timedelta(minutes=5)
        }
        
        # Remove any existing registration OTP for this email
        otp_collection.delete_many({"email": request.email, "type": "registration"})
        
        # Store new OTP
        result = otp_collection.insert_one(otp_data)
        logger.info(f"🔑 Registration OTP generated and stored for: {request.email} - expires in 5 minutes")
        
        # Send OTP email with registration context
        email_sent = send_registration_otp_email(request.email, otp)
        
        if email_sent:
            logger.info(f"✅ Registration OTP email sent successfully to: {request.email}")
            return {
                "message": "OTP sent successfully to your email address for registration verification", 
                "expiresIn": 300,  # 300 seconds = 5 minutes
                "email_sent": True
            }
        else:
            logger.error(f"❌ Failed to send registration OTP email to: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP email. Please check your email configuration or try again later."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Send registration OTP error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

class RegistrationWithOTP(BaseModel):
    # User data
    name: str
    email: EmailStr
    gender: str
    age: int
    permanentAddress: str
    presentAddress: str
    workingCity: str
    pincode: str
    userType: str
    phone: str
    bio: str
    skills: Optional[List[str]] = []
    rating: float = 0.0
    yearsOfExperience: Optional[int] = 0
    photo: Optional[str] = None
    idProof: Optional[str] = None
    # OTP verification
    otp: str

@app.post("/register", response_model=UserResponse)
async def register_user(user_data: RegistrationWithOTP):
    try:
        logger.info(f"📝 Registration attempt for email: {user_data.email}")
        
        # First, verify the OTP
        otp_data = otp_collection.find_one({
            "email": user_data.email,
            "otp": user_data.otp,
            "type": "registration",
            "expiresAt": {"$gt": datetime.utcnow()}
        })
        
        if not otp_data:
            logger.warning(f"⚠️ Invalid or expired registration OTP for: {user_data.email}")
            
            # Check if there's any OTP for this email (expired or not)
            any_otp = otp_collection.find_one({
                "email": user_data.email,
                "type": "registration"
            })
            
            if any_otp:
                if any_otp["expiresAt"] <= datetime.utcnow():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Your OTP has expired. Please request a new OTP and try again."
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid OTP. Please check the code and try again."
                    )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No valid OTP found. Please request a new OTP and try again."
                )
        
        # Check if email already exists (double-check)
        existing_user = users_collection.find_one({"email": user_data.email})
        if existing_user:
            logger.warning(f"⚠️ Email already registered: {user_data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Check if phone already exists
        existing_phone = users_collection.find_one({"phone": user_data.phone})
        if existing_phone:
            logger.warning(f"⚠️ Phone already registered: {user_data.phone}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number already registered"
            )
        
        # Validate age
        if user_data.age < 18:
            logger.warning(f"⚠️ Underage registration attempt: {user_data.age}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must be at least 18 years old"
            )
        
        # Create new user (exclude OTP from user data)
        user_dict = user_data.dict(exclude={"otp"})
        user_dict["createdAt"] = datetime.utcnow()
        
        logger.info(f"💾 Creating user with data: {user_dict}")
        
        # Insert into database
        result = users_collection.insert_one(user_dict)
        logger.info(f"✅ User created with ID: {result.inserted_id}")
        
        # Delete the used OTP
        otp_collection.delete_one({"_id": otp_data["_id"]})
        logger.info(f"🗑️ Registration OTP deleted for: {user_data.email}")
        
        # Return user
        created_user = users_collection.find_one({"_id": result.inserted_id})
        if not created_user:
            logger.error("❌ Failed to retrieve created user")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
        
        # Send welcome email
        try:
            logger.info(f"📧 Sending welcome email to: {user_data.email}")
            email_sent = send_welcome_email(user_data.email, user_data.name, user_data.userType)
            
            if email_sent:
                logger.info(f"✅ Welcome email sent successfully to: {user_data.email}")
            else:
                logger.warning(f"⚠️ Failed to send welcome email to: {user_data.email}")
                # Don't fail registration if email fails
                
        except Exception as email_error:
            logger.error(f"❌ Welcome email error: {email_error}")
            # Don't fail registration if email fails
        
        logger.info(f"🎉 Registration successful for: {user_data.email}")
        return serialize_id(created_user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

def send_registration_otp_email(email: str, otp: str):
    """Send OTP email for registration verification"""
    subject = "Workers Globe - Email Verification Code"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=width-device, initial-scale=1.0">
        <title>Workers Globe - Email Verification</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 30px; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 32px; font-weight: bold;">Workers Globe</h1>
                <p style="color: #d1fae5; margin: 15px 0 0 0; font-size: 18px;">Email Verification Required</p>
            </div>
            
            <!-- Main Content -->
            <div style="padding: 40px 30px;">
                <div style="background: #f9fafb; padding: 30px; border-radius: 12px; border-left: 4px solid #10b981;">
                    <h2 style="color: #1f2937; margin-top: 0; font-size: 24px;">Verify Your Email Address</h2>
                    <p style="color: #4b5563; font-size: 16px; line-height: 1.6; margin: 20px 0;">
                        Thank you for choosing Workers Globe! To complete your registration, please verify your email address by entering the verification code below:
                    </p>
                    
                    <!-- OTP Box -->
                    <div style="background: white; padding: 25px; border-radius: 10px; text-align: center; margin: 30px 0; border: 2px dashed #10b981; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="font-size: 36px; font-weight: bold; color: #10b981; letter-spacing: 8px; font-family: 'Courier New', monospace;">{otp}</div>
                    </div>
                    
                    <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 15px; margin: 20px 0;">
                        <p style="color: #dc2626; font-size: 14px; margin: 0; font-weight: 500;">
                            ⏰ This verification code will expire in 5 minutes for security purposes.
                        </p>
                    </div>
                    
                    <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 15px; margin: 20px 0;">
                        <p style="color: #166534; font-size: 14px; margin: 0; font-weight: 500;">
                            📝 Enter this code in the registration form to verify your email and complete your account setup.
                        </p>
                    </div>
                    
                    <p style="color: #6b7280; font-size: 14px; line-height: 1.5;">
                        If you didn't request this verification code, please ignore this email.
                    </p>
                </div>
                
                <!-- Security Notice -->
                <div style="margin-top: 30px; padding: 20px; background: #eff6ff; border-radius: 8px; border-left: 4px solid #3b82f6;">
                    <h3 style="color: #1e40af; margin: 0 0 10px 0; font-size: 16px;">Security Notice</h3>
                    <p style="color: #1e40af; font-size: 14px; margin: 0; line-height: 1.4;">
                        Workers Globe will never ask you to share your verification code with anyone. Keep this code confidential.
                    </p>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 14px; margin: 0 0 10px 0;">
                    This email was sent to {email}
                </p>
                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                    © 2024 Workers Globe. All rights reserved.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body)

# Helper functions for job matching and ranking
def calculate_job_match_score(job, user):
    """Calculate how well a job matches a user's profile"""
    score = 0
    
    # Skills matching (60% weight) - Updated for standardized skills
    user_skills = set()
    for skill in user.get("skills", []):
        # Normalize skill names for better matching
        normalized_skill = skill.lower().strip()
        user_skills.add(normalized_skill)
        
        # Also add variations for better matching
        skill_variations = {
            "farming labour": ["farming", "agriculture", "farm work", "agricultural"],
            "construction labour": ["construction", "building", "labor"],
            "mason": ["masonry", "bricklayer"],
            "carpenter": ["carpentry", "woodwork"],
            "electrician": ["electrical", "wiring"],
            "gardener": ["gardening", "landscaping"],
            "domestic cook": ["cooking", "chef", "kitchen"],
            "driver": ["driving", "transport"],
            "plumber": ["plumbing", "pipes"],
            "security guard": ["security", "guard"]
        }
        
        if normalized_skill in skill_variations:
            user_skills.update(skill_variations[normalized_skill])
    
    # Job title matching (enhanced for new dropdown system)
    job_title = job.get("title", "").lower().strip()
    if job_title in user_skills:
        score += 60
    else:
        # Check for skill variations in job title
        for skill, variations in {
            "farming labour": ["farming", "agriculture", "farm work", "agricultural"],
            "construction labour": ["construction", "building", "labor"],
            "mason": ["masonry", "bricklayer"],
            "carpenter": ["carpentry", "woodwork"],
            "electrician": ["electrical", "wiring"],
            "gardener": ["gardening", "landscaping"],
            "domestic cook": ["cooking", "chef", "kitchen"],
            "driver": ["driving", "transport"],
            "plumber": ["plumbing", "pipes"],
            "security guard": ["security", "guard"]
        }.items():
            if job_title == skill.lower() and any(var in user_skills for var in variations):
                score += 60
                break
    
    # Experience matching (20% weight)
    user_experience = user.get("yearsOfExperience", 0)
    preferred_experience = job.get("preferredExperience", 0)
    
    if preferred_experience:
        if user_experience >= preferred_experience:
            score += 20
        else:
            score += (user_experience / preferred_experience) * 20
    else:
        score += 20  # No experience requirement
    
    # Location matching (10% weight)
    if user.get("workingCity", "").lower() == job.get("location", "").lower():
        score += 10
    
    # Rating bonus (10% weight)
    user_rating = user.get("rating", 0)
    score += (user_rating / 5) * 10
    
    return min(score, 100)  # Cap at 100%

def calculate_seeker_ranking_score(seeker, job):
    """Calculate ranking score for a seeker applying to a job"""
    score = 0
    
    # Skills matching (60% weight) - Updated for standardized skills
    seeker_skills = set()
    for skill in seeker.get("skills", []):
        normalized_skill = skill.lower().strip()
        seeker_skills.add(normalized_skill)
        
        # Add skill variations
        skill_variations = {
            "farming labour": ["farming", "agriculture", "farm work"],
            "construction labour": ["construction", "building", "labor"],
            "mason": ["masonry", "bricklayer"],
            "carpenter": ["carpentry", "woodwork"],
            "electrician": ["electrical", "wiring"],
            "gardener": ["gardening", "landscaping"],
            "domestic cook": ["cooking", "chef", "kitchen"],
            "driver": ["driving", "transport"],
            "plumber": ["plumbing", "pipes"],
            "security guard": ["security", "guard"]
        }
        
        if normalized_skill in skill_variations:
            seeker_skills.update(skill_variations[normalized_skill])
    
    # Job title matching (enhanced for new dropdown system)
    job_title = job.get("title", "").lower().strip()
    if job_title in seeker_skills:
        score += 60
    else:
        # Check for skill variations in job title
        for skill, variations in {
            "farming labour": ["farming", "agriculture", "farm work"],
            "construction labour": ["construction", "building", "labor"],
            "mason": ["masonry", "bricklayer"],
            "carpenter": ["carpentry", "woodwork"],
            "electrician": ["electrical", "wiring"],
            "gardener": ["gardening", "landscaping"],
            "domestic cook": ["cooking", "chef", "kitchen"],
            "driver": ["driving", "transport"],
            "plumber": ["plumbing", "pipes"],
            "security guard": ["security", "guard"]
        }.items():
            if job_title == skill.lower() and any(var in seeker_skills for var in variations):
                score += 60
                break
    
    # Experience matching (10% weight)
    seeker_experience = seeker.get("yearsOfExperience", 0)
    preferred_experience = job.get("preferredExperience", 0)
    
    if preferred_experience:
        if seeker_experience >= preferred_experience:
            score += 10
        else:
            score += (seeker_experience / preferred_experience) * 10
    else:
        score += 10
    
    # Rating (20% weight)
    seeker_rating = seeker.get("rating", 0)
    score += (seeker_rating / 5) * 20
    
    return min(score, 100)

def send_job_match_email(email: str, job: dict, match_score: float):
    """Send email notification for job matches with enhanced details"""
    subject = f"New Job Match - {job['title']} ({match_score:.0f}% Match)"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Workers Globe - New Job Match</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 30px; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 32px; font-weight: bold;">🎯 Perfect Job Match!</h1>
                <p style="color: #d1fae5; margin: 15px 0 0 0; font-size: 18px;">{match_score:.0f}% Match with Your Skills</p>
            </div>
            
            <!-- Main Content -->
            <div style="padding: 40px 30px;">
                <!-- Custom Message -->
                <div style="background: #f0fdf4; padding: 25px; border-radius: 12px; border-left: 4px solid #10b981; margin-bottom: 30px;">
                    <h2 style="color: #166534; margin-top: 0; font-size: 24px;">Great News!</h2>
                    <p style="color: #166534; font-size: 16px; line-height: 1.6; margin: 15px 0;">
                        A new job matching your skills has just been posted! Based on your profile and experience, 
                        this opportunity is a <strong>{match_score:.0f}% match</strong> for you.
                    </p>
                </div>
                
                <!-- Job Details -->
                <div style="background: #f9fafb; padding: 30px; border-radius: 12px; margin-bottom: 30px;">
                    <h3 style="color: #1f2937; margin-top: 0; font-size: 20px; margin-bottom: 20px;">📋 Job Details</h3>
                    
                    <div style="margin-bottom: 20px;">
                        <h4 style="color: #374151; margin: 0 0 8px 0; font-size: 18px; font-weight: bold;">{job['title']}</h4>
                        <p style="color: #6b7280; margin: 0; font-size: 14px;">
                            <strong>Company:</strong> {job.get('providerName', 'Employer Name')}
                        </p>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 15px;">
                            <div style="background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; flex: 1; min-width: 120px;">
                                <div style="color: #6b7280; font-size: 12px; font-weight: 500; text-transform: uppercase; margin-bottom: 4px;">Location</div>
                                <div style="color: #1f2937; font-weight: 600;">{job.get('location', 'Not specified')}</div>
                            </div>
                            <div style="background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; flex: 1; min-width: 120px;">
                                <div style="color: #6b7280; font-size: 12px; font-weight: 500; text-transform: uppercase; margin-bottom: 4px;">Payment</div>
                                <div style="color: #1f2937; font-weight: 600;">₹{job.get('payment', 'Negotiable')}</div>
                            </div>
                            <div style="background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; flex: 1; min-width: 120px;">
                                <div style="color: #6b7280; font-size: 12px; font-weight: 500; text-transform: uppercase; margin-bottom: 4px;">Duration</div>
                                <div style="color: #1f2937; font-weight: 600;">{job.get('duration', 'Not specified')}</div>
                            </div>
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h5 style="color: #374151; margin: 0 0 10px 0; font-size: 14px; font-weight: 600;">Job Description:</h5>
                        <div style="color: #6b7280; line-height: 1.6; padding: 15px; background: white; border-radius: 8px; border: 1px solid #e5e7eb;">
                            {job.get('description', 'No description available')[:200]}{'...' if len(job.get('description', '')) > 200 else ''}
                        </div>
                    </div>
                    
                    <!-- Match Details -->
                    <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 15px; margin: 20px 0;">
                        <h5 style="color: #1e40af; margin: 0 0 8px 0; font-size: 14px; font-weight: 600;">🎯 Why This Job Matches You:</h5>
                        <p style="color: #1e40af; font-size: 13px; margin: 0; line-height: 1.4;">
                            This job matches your skills and experience profile. Your expertise in relevant areas makes you a strong candidate for this position.
                        </p>
                    </div>
                </div>
                
                <!-- Call to Action -->
                <div style="text-align: center; margin: 30px 0;">
                    <a href="http://localhost:5173/job/{job.get('id', '')}" 
                       style="display: inline-block; background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(16, 185, 129, 0.3);">
                        🔍 View Full Job Details & Apply
                    </a>
                </div>
                
                <!-- Alternative Link -->
                <div style="text-align: center; margin: 20px 0;">
                    <p style="color: #6b7280; font-size: 14px; margin: 0;">
                        Or copy this link: 
                        <a href="http://localhost:5173/job/{job.get('id', '')}" style="color: #10b981; text-decoration: none; font-weight: 500;">
                            http://localhost:5173/job/{job.get('id', '')}
                        </a>
                    </p>
                </div>
                
                <!-- Instructions -->
                <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 10px; padding: 20px; margin: 20px 0;">
                    <h4 style="color: #1e40af; margin: 0 0 10px 0; font-size: 16px;">📝 Next Steps:</h4>
                    <ul style="color: #1e40af; font-size: 14px; margin: 10px 0; padding-left: 20px; line-height: 1.6;">
                        <li>Click the button above to view the complete job details</li>
                        <li>Review the full job requirements and description</li>
                        <li>Apply directly through the platform if interested</li>
                        <li>Contact the employer for any questions</li>
                    </ul>
                </div>
                
                <!-- Tips -->
                <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 15px; margin: 20px 0;">
                    <h4 style="color: #92400e; margin: 0 0 8px 0; font-size: 14px;">💡 Application Tips:</h4>
                    <p style="color: #92400e; font-size: 13px; margin: 0; line-height: 1.4;">
                        Apply quickly for the best chance of selection. Make sure your profile is complete and highlights your relevant experience.
                    </p>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 14px; margin: 0 0 10px 0;">
                    This email was sent to {email}
                </p>
                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                    © 2024 Workers Globe. All rights reserved.
                </p>
                <div style="margin-top: 15px;">
                    <p style="color: #6b7280; font-size: 13px; margin: 0;">
                        <a href="http://localhost:5173" style="color: #10b981; text-decoration: none;">Visit Workers Globe</a> | 
                        <a href="http://localhost:5173/login" style="color: #10b981; text-decoration: none;">Login</a> |
                        <a href="http://localhost:5173/profile" style="color: #10b981; text-decoration: none;">Update Profile</a>
                    </p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body)

def send_application_notification_email(email: str, job: dict, total_applicants: int):
    """Send email notification for new applications without personal details"""
    subject = f"New Application - {job['title']}"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Workers Globe - New Application</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 30px; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 32px; font-weight: bold;">🎉 New Application!</h1>
                <p style="color: #d1fae5; margin: 15px 0 0 0; font-size: 18px;">A new candidate has applied for your job posting</p>
            </div>
            
            <!-- Main Content -->
            <div style="padding: 40px 30px;">
                <!-- Custom Message -->
                <div style="background: #f0fdf4; padding: 25px; border-radius: 12px; border-left: 4px solid #10b981; margin-bottom: 30px;">
                    <h2 style="color: #166534; margin-top: 0; font-size: 24px;">Great News!</h2>
                    <p style="color: #166534; font-size: 16px; line-height: 1.6; margin: 15px 0;">
                        A new candidate has applied for your job posting. You now have <strong>{total_applicants} applicant(s)</strong> for this position.
                    </p>
                </div>
                
                <!-- Job Details -->
                <div style="background: #f9fafb; padding: 30px; border-radius: 12px; margin-bottom: 30px;">
                    <h3 style="color: #1f2937; margin-top: 0; font-size: 20px; margin-bottom: 20px;">📋 Job Details</h3>
                    
                    <div style="margin-bottom: 15px;">
                        <strong style="color: #374151;">Job ID:</strong>
                        <span style="color: #6b7280; font-family: 'Courier New', monospace; background: #e5e7eb; padding: 2px 6px; border-radius: 4px; margin-left: 10px;">{job.get('id', 'N/A')}</span>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <strong style="color: #374151;">Job Title:</strong>
                        <span style="color: #6b7280; margin-left: 10px;">{job['title']}</span>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <strong style="color: #374151;">Location:</strong>
                        <span style="color: #6b7280; margin-left: 10px;">{job.get('location', 'N/A')}</span>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <strong style="color: #374151;">Payment:</strong>
                        <span style="color: #6b7280; margin-left: 10px;">₹{job.get('payment', 'N/A')}</span>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <strong style="color: #374151;">Description:</strong>
                        <div style="color: #6b7280; margin-top: 8px; padding: 15px; background: white; border-radius: 8px; border: 1px solid #e5e7eb; line-height: 1.6;">
                            {job.get('description', 'No description available')}
                        </div>
                    </div>
                </div>
                
                <!-- Call to Action -->
                <div style="text-align: center; margin: 30px 0;">
                    <a href="http://localhost:5173/login" 
                       style="display: inline-block; background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(16, 185, 129, 0.3);">
                        🔐 Login to View Application Details
                    </a>
                </div>
                
                <!-- Instructions -->
                <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 10px; padding: 20px; margin: 20px 0;">
                    <h4 style="color: #1e40af; margin: 0 0 10px 0; font-size: 16px;">📝 Next Steps:</h4>
                    <ul style="color: #1e40af; font-size: 14px; margin: 10px 0; padding-left: 20px; line-height: 1.6;">
                        <li>Click the login button above to access your account</li>
                        <li>Navigate to your Job Provider Dashboard</li>
                        <li>View all applications for this job posting</li>
                        <li>Review candidate profiles and select the best fit</li>
                    </ul>
                </div>
                
                <!-- Privacy Notice -->
                <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 15px; margin: 20px 0;">
                    <h4 style="color: #dc2626; margin: 0 0 8px 0; font-size: 14px;">🔒 Privacy & Security</h4>
                    <p style="color: #dc2626; font-size: 13px; margin: 0; line-height: 1.4;">
                        For privacy and security reasons, candidate details are only available after you log in to your account. 
                        This ensures that personal information remains protected.
                    </p>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 14px; margin: 0 0 10px 0;">
                    This email was sent to {email}
                </p>
                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                    © 2024 Workers Globe. All rights reserved.
                </p>
                <div style="margin-top: 15px;">
                    <p style="color: #6b7280; font-size: 13px; margin: 0;">
                        <a href="http://localhost:5173" style="color: #10b981; text-decoration: none;">Visit Workers Globe</a> | 
                        <a href="http://localhost:5173/login" style="color: #10b981; text-decoration: none;">Login</a>
                    </p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body)

def send_selection_notification_email(email: str, job_title: str, provider_name: str):
    """Send email notification for job selection"""
    subject = f"Congratulations! You've been selected for {job_title}"
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
            <h1 style="color: white; margin: 0; font-size: 28px;">Congratulations!</h1>
        </div>
        
        <div style="background: #f9fafb; padding: 30px; border-radius: 10px;">
            <h2 style="color: #1f2937; margin-top: 0;">You've been selected for {job_title}</h2>
            <p style="color: #4b5563; font-size: 16px;">
                {provider_name} has selected you for this job. Please contact them to discuss next steps.
            </p>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body)

def send_job_completion_email(email: str, job_title: str, rating: int, feedback: str, is_provider: bool, job_details: dict = None):
    """Send email notification for job completion with enhanced content"""
    
    if is_provider:
        # Provider completion email (keep existing simple format)
        role = "provider"
        subject = f"Job Completed - {job_title}"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
                <h1 style="color: white; margin: 0; font-size: 28px;">Job Completed</h1>
            </div>
            
            <div style="background: #f9fafb; padding: 30px; border-radius: 10px;">
                <h2 style="color: #1f2937; margin-top: 0;">{job_title}</h2>
                <p style="color: #4b5563; font-size: 16px;">
                    You received a {rating}-star rating.
                </p>
                <p style="color: #4b5563; font-size: 16px;">
                    <strong>Feedback:</strong> {feedback}
                </p>
            </div>
        </body>
        </html>
        """
    else:
        # Enhanced job seeker completion email
        subject = f"🎉 Congratulations! Job Completed Successfully - {job_title}"
        
        # Get star display
        star_display = "⭐" * rating + "☆" * (5 - rating)
        
        # Get job details
        company_name = job_details.get('providerName', 'Company') if job_details else 'Company'
        job_id = job_details.get('id', 'N/A') if job_details else 'N/A'
        location = job_details.get('location', 'N/A') if job_details else 'N/A'
        payment = job_details.get('payment', 'N/A') if job_details else 'N/A'
        
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Workers Globe - Job Completion Congratulations</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 32px; font-weight: bold;">🎉 Congratulations!</h1>
                    <p style="color: #d1fae5; margin: 15px 0 0 0; font-size: 18px;">Job Successfully Completed</p>
                </div>
                
                <!-- Main Content -->
                <div style="padding: 40px 30px;">
                    <!-- Congratulatory Message -->
                    <div style="background: #f0fdf4; padding: 30px; border-radius: 12px; border-left: 4px solid #10b981; margin-bottom: 30px;">
                        <h2 style="color: #166534; margin-top: 0; font-size: 24px;">Outstanding Work! 🌟</h2>
                        <p style="color: #166534; font-size: 16px; line-height: 1.6; margin: 15px 0;">
                            We're thrilled to inform you that you have successfully completed your job assignment! 
                            Your dedication and hard work have been recognized, and we truly appreciate your 
                            commitment to delivering quality work through the Workers Globe platform.
                        </p>
                    </div>
                    
                    <!-- Job Details Summary -->
                    <div style="background: #f9fafb; padding: 30px; border-radius: 12px; margin-bottom: 30px;">
                        <h3 style="color: #1f2937; margin-top: 0; font-size: 20px; margin-bottom: 20px;">📋 Job Completion Summary</h3>
                        
                        <div style="margin-bottom: 20px;">
                            <h4 style="color: #374151; margin: 0 0 8px 0; font-size: 18px; font-weight: bold;">{job_title}</h4>
                            <p style="color: #6b7280; margin: 0; font-size: 14px;">
                                <strong>Company:</strong> {company_name}
                            </p>
                        </div>
                        
                        <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 20px;">
                            <div style="background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; flex: 1; min-width: 120px;">
                                <div style="color: #6b7280; font-size: 12px; font-weight: 500; text-transform: uppercase; margin-bottom: 4px;">Job ID</div>
                                <div style="color: #1f2937; font-weight: 600; font-family: 'Courier New', monospace;">{job_id}</div>
                            </div>
                            <div style="background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; flex: 1; min-width: 120px;">
                                <div style="color: #6b7280; font-size: 12px; font-weight: 500; text-transform: uppercase; margin-bottom: 4px;">Location</div>
                                <div style="color: #1f2937; font-weight: 600;">{location}</div>
                            </div>
                            <div style="background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; flex: 1; min-width: 120px;">
                                <div style="color: #6b7280; font-size: 12px; font-weight: 500; text-transform: uppercase; margin-bottom: 4px;">Payment</div>
                                <div style="color: #1f2937; font-weight: 600;">₹{payment}</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Performance Summary -->
                    <div style="background: #eff6ff; padding: 30px; border-radius: 12px; border-left: 4px solid #3b82f6; margin-bottom: 30px;">
                        <h3 style="color: #1e40af; margin-top: 0; font-size: 20px; margin-bottom: 20px;">⭐ Your Performance Summary</h3>
                        
                        <!-- Rating Display -->
                        <div style="background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; text-align: center;">
                            <div style="font-size: 24px; margin-bottom: 10px;">{star_display}</div>
                            <div style="color: #1e40af; font-size: 18px; font-weight: bold; margin-bottom: 5px;">
                                {rating} out of 5 Stars
                            </div>
                            <div style="color: #6b7280; font-size: 14px;">
                                Rating from {company_name}
                            </div>
                        </div>
                        
                        <!-- Feedback Section -->
                        <div style="background: white; padding: 20px; border-radius: 10px;">
                            <h4 style="color: #1e40af; margin: 0 0 10px 0; font-size: 16px; font-weight: 600;">💬 Employer Feedback:</h4>
                            <div style="color: #374151; line-height: 1.6; padding: 15px; background: #f8fafc; border-radius: 8px; border-left: 3px solid #3b82f6; font-style: italic;">
                                "{feedback}"
                            </div>
                        </div>
                    </div>
                    
                    <!-- Achievement Badge -->
                    <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 12px; padding: 25px; margin: 30px 0; text-align: center;">
                        <div style="font-size: 48px; margin-bottom: 10px;">🏆</div>
                        <h3 style="color: #92400e; margin: 0 0 10px 0; font-size: 18px; font-weight: bold;">Job Completion Achievement</h3>
                        <p style="color: #92400e; font-size: 14px; margin: 0; line-height: 1.5;">
                            You've successfully completed another job on Workers Globe! This achievement has been added to your profile 
                            and will help build your reputation for future opportunities.
                        </p>
                    </div>
                    
                    <!-- Call to Action -->
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="http://localhost:5173/login" 
                           style="display: inline-block; background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(16, 185, 129, 0.3); margin-right: 15px;">
                            🔍 Find More Jobs
                        </a>
                        <a href="http://localhost:5173/profile" 
                           style="display: inline-block; background: #6b7280; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                            📊 View Profile
                        </a>
                    </div>
                    
                    <!-- Encouragement Section -->
                    <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 10px; padding: 25px; margin: 30px 0;">
                        <h4 style="color: #166534; margin: 0 0 15px 0; font-size: 18px; font-weight: bold;">🚀 Keep Up the Great Work!</h4>
                        <p style="color: #166534; font-size: 15px; margin: 0 0 15px 0; line-height: 1.6;">
                            Your successful job completion demonstrates your reliability and skill. Here's how you can continue growing on Workers Globe:
                        </p>
                        <ul style="color: #166534; font-size: 14px; margin: 0; padding-left: 20px; line-height: 1.8;">
                            <li>Browse and apply for new job opportunities that match your skills</li>
                            <li>Update your profile with any new skills or experience gained</li>
                            <li>Maintain your excellent rating by continuing to deliver quality work</li>
                            <li>Build long-term relationships with employers for repeat opportunities</li>
                        </ul>
                    </div>
                    
                    <!-- Platform Benefits -->
                    <div style="background: #f3f4f6; padding: 25px; border-radius: 10px; margin: 30px 0;">
                        <h4 style="color: #374151; margin: 0 0 15px 0; font-size: 16px; font-weight: bold;">🌟 Why Employers Choose Workers Globe Professionals:</h4>
                        <div style="display: flex; flex-wrap: wrap; gap: 15px;">
                            <div style="flex: 1; min-width: 200px; background: white; padding: 15px; border-radius: 8px; border-left: 3px solid #10b981;">
                                <div style="color: #10b981; font-weight: bold; margin-bottom: 5px;">✅ Verified Skills</div>
                                <div style="color: #6b7280; font-size: 13px;">Your completed jobs showcase your abilities</div>
                            </div>
                            <div style="flex: 1; min-width: 200px; background: white; padding: 15px; border-radius: 8px; border-left: 3px solid #3b82f6;">
                                <div style="color: #3b82f6; font-weight: bold; margin-bottom: 5px;">⭐ Proven Track Record</div>
                                <div style="color: #6b7280; font-size: 13px;">Your ratings build trust with new employers</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Support Section -->
                    <div style="background: #f9fafb; padding: 20px; border-radius: 8px; text-align: center; margin-top: 30px;">
                        <h4 style="color: #374151; margin: 0 0 10px 0; font-size: 16px;">Need Support or Have Questions?</h4>
                        <p style="color: #6b7280; font-size: 14px; margin: 0; line-height: 1.5;">
                            Our support team is here to help you succeed. If you have any questions about your completed job, 
                            payment, or finding new opportunities, don't hesitate to reach out.
                        </p>
                    </div>
                </div>
                
                <!-- Footer -->
                <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="color: #9ca3af; font-size: 14px; margin: 0 0 10px 0;">
                        This email was sent to {email}
                    </p>
                    <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                        © 2024 Workers Globe. All rights reserved.
                    </p>
                    <div style="margin-top: 20px;">
                        <p style="color: #6b7280; font-size: 14px; margin: 0;">
                            <a href="http://localhost:5173" style="color: #10b981; text-decoration: none; font-weight: bold;">Continue Your Journey on Workers Globe</a>
                        </p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    
    return send_email(email, subject, body)

# Add a root endpoint
@app.get("/")
async def root():
    return {
        "message": "Workers Globe API is running!",
        "version": "2.4.0",
        "timestamp": datetime.utcnow(),
        "email_enabled": ENABLE_EMAIL_SENDING,
        "features": [
            "OTP-based authentication",
            "Registration email verification",
            "Welcome email system",
            "Standardized job titles",
            "Enhanced job matching",
            "Email delivery system",
            "Manual location entry",
            "Experience dropdown",
            "Admin authentication",
            "Multi-language support"
        ],
        "endpoints": {
            "health": "/health",
            "test": "/test",
            "register": "/register",
            "register_send_otp": "/register/send-otp",
            "send_otp": "/send-otp",
            "verify_otp": "/verify-otp",
            "db_status": "/db-status"
        }
    }

# Add a health check endpoint
@app.get("/health")
async def health_check():
    try:
        # Test database connection
        client.admin.command('ping')
        logger.info("🏥 Health check passed")
        return {
            "status": "healthy",
            "database": "connected",
            "email_configured": bool(EMAIL_USER and EMAIL_PASSWORD),
            "email_enabled": ENABLE_EMAIL_SENDING,
            "timestamp": datetime.utcnow()
        }
    except Exception as e:
        logger.error(f"🏥 Health check failed: {e}")
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow()
        }

# Add a test endpoint
@app.get("/test")
async def test_endpoint():
    logger.info("🧪 Test endpoint called")
    return {
        "message": "API is working perfectly!",
        "timestamp": datetime.utcnow(),
        "server": "FastAPI",
        "database": "MongoDB",
        "email_status": "enabled" if ENABLE_EMAIL_SENDING else "disabled",
        "features": "OTP Authentication, Registration email verification, Standardized job titles, Welcome Emails, Email Delivery, Manual Location, Experience Dropdown"
    }

# Email test endpoint
@app.post("/test-email")
async def test_email_endpoint(request: OTPRequest):
    """Test endpoint to verify email functionality"""
    try:
        # Generate a test OTP
        test_otp = "123456"
        
        # Send test email
        email_sent = send_otp_email(request.email, test_otp)
        
        if email_sent:
            return {
                "status": "success",
                "message": f"Test email sent successfully to {request.email}",
                "email_enabled": ENABLE_EMAIL_SENDING
            }
        else:
            return {
                "status": "error",
                "message": "Failed to send test email. Please check email configuration.",
                "email_enabled": ENABLE_EMAIL_SENDING
            }
    except Exception as e:
        logger.error(f"❌ Test email error: {e}")
        return {
            "status": "error",
            "message": f"Error: {str(e)}",
            "email_enabled": ENABLE_EMAIL_SENDING
        }

@app.post("/send-otp")
async def send_otp(request: OTPRequest):
    try:
        logger.info(f"📧 OTP request for email: {request.email}")
        
        # Check if user exists
        user = users_collection.find_one({"email": request.email})
        if not user:
            logger.warning(f"⚠️ OTP requested for non-existent user: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found. Please register first."
            )
        
        # Generate and store OTP with 5 minute expiry
        otp = generate_otp()
        otp_data = {
            "email": request.email,
            "otp": otp,
            "createdAt": datetime.utcnow(),
            "expiresAt": datetime.utcnow() + timedelta(minutes=5)
        }
        
        # Remove any existing OTP for this email
        otp_collection.delete_many({"email": request.email})
        
        # Store new OTP
        result = otp_collection.insert_one(otp_data)
        logger.info(f"🔑 OTP generated and stored for: {request.email} - expires in 5 minutes")
        
        # Send OTP email
        email_sent = send_otp_email(request.email, otp)
        
        if email_sent:
            logger.info(f"✅ OTP email sent successfully to: {request.email}")
            return {
                "message": "OTP sent successfully to your email address", 
                "expiresIn": 300,  # 300 seconds = 5 minutes
                "email_sent": True
            }
        else:
            logger.error(f"❌ Failed to send OTP email to: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP email. Please check your email configuration or try again later."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Send OTP error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@app.post("/verify-otp", response_model=Token)
async def verify_otp(request: OTPVerification):
    try:
        logger.info(f"🔐 OTP verification for email: {request.email}")
        
        # Find OTP
        otp_data = otp_collection.find_one({
            "email": request.email,
            "otp": request.otp,
            "expiresAt": {"$gt": datetime.utcnow()}
        })
        
        if not otp_data:
            logger.warning(f"⚠️ Invalid or expired OTP for: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        # Get user
        user = users_collection.find_one({"email": request.email})
        if not user:
            logger.error(f"❌ User not found during OTP verification: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Delete used OTP
        otp_collection.delete_one({"_id": otp_data["_id"]})
        
        # Generate access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"]}, expires_delta=access_token_expires
        )
        
        logger.info(f"🎉 OTP verification successful for: {request.email}")
        return {"access_token": access_token, "token_type": "bearer"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ OTP verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    logger.info(f"👤 User profile requested for: {current_user['email']}")
    return current_user

# Add database status endpoint
@app.get("/db-status")
async def database_status():
    try:
        # Test database operations
        users_count = users_collection.count_documents({})
        jobs_count = jobs_collection.count_documents({})
        
        logger.info("📊 Database status check successful")
        return {
            "status": "connected",
            "database": "village_jobs",
            "collections": {
                "users": users_count,
                "jobs": jobs_count,
                "applications": applications_collection.count_documents({}),
                "notifications": notifications_collection.count_documents({}),
                "payments": payments_collection.count_documents({}),
                "otps": otp_collection.count_documents({})
            }
        }
    except Exception as e:
        logger.error(f"❌ Database status check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

@app.put("/users/me", response_model=UserResponse)
async def update_user(
    user_update: UserBase,
    current_user: dict = Depends(get_current_user)
):
    # Update user
    user_dict = user_update.dict(exclude_unset=True)
    users_collection.update_one(
        {"_id": ObjectId(current_user["id"])},
        {"$set": user_dict}
    )
    
    # Return updated user
    updated_user = users_collection.find_one({"_id": ObjectId(current_user["id"])})
    return serialize_id(updated_user)

# ENHANCED JOB CREATION ENDPOINT WITH STANDARDIZED TITLES
@app.post("/jobs", response_model=JobResponse)
async def create_job(
    job: JobCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        logger.info(f"💼 Job creation request from user: {current_user['email']}")
        logger.info(f"📝 Job data received: {job.dict()}")
        
        # Check if user is a provider
        if current_user["userType"] != "provider":
            logger.warning(f"⚠️ Non-provider user attempted to create job: {current_user['email']}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only job providers can create jobs"
            )
        
        # Validate job title against predefined list
        valid_job_titles = [
            "Farming Labour",
            "Construction Labour", 
            "Mason",
            "Carpenter",
            "Electrician",
            "Gardener",
            "Domestic Cook",
            "Driver",
            "Plumber",
            "Security Guard"
        ]
        
        if job.title not in valid_job_titles:
            logger.warning(f"⚠️ Invalid job title attempted: {job.title}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid job title. Must be one of: {', '.join(valid_job_titles)}"
            )
        
        # Create job
        job_dict = job.dict()
        job_dict["providerId"] = current_user["id"]
        job_dict["providerName"] = current_user["name"]
        job_dict["status"] = "open"
        job_dict["createdAt"] = datetime.utcnow()
        job_dict["applicants"] = 0
        
        # Set category based on job title for backward compatibility
        job_dict["category"] = job.title
        
        # Set required skills based on job title
        job_dict["requiredSkills"] = [job.title.lower()]
        
        logger.info(f"💾 Inserting job into database: {job_dict}")
        
        # Insert into database
        result = jobs_collection.insert_one(job_dict)
        logger.info(f"✅ Job created with ID: {result.inserted_id}")
        
        # Retrieve the created job
        created_job = jobs_collection.find_one({"_id": result.inserted_id})
        if not created_job:
            logger.error("❌ Failed to retrieve created job")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create job"
            )
        
        created_job = serialize_id(created_job)
        
        # Find matching job seekers and send emails
        if job.jobStatus == "OPEN":
            logger.info("📧 Finding matching job seekers...")
            matching_users = users_collection.find({"userType": "seeker"})
            
            for user in matching_users:
                match_score = calculate_job_match_score(created_job, user)
                
                # Send email if match score is above threshold (e.g., 60%)
                if match_score >= 60:
                    logger.info(f"📧 Sending job match email to {user['email']} (match: {match_score:.0f}%)")
                    send_job_match_email(user["email"], created_job, match_score)
                    
                    # Create notification
                    notification = {
                        "userId": str(user["_id"]),
                        "type": "new-matching-job",
                        "title": "New Job Match",
                        "message": f"A new job matching your profile ({match_score:.0f}% match): {job.title}",
                        "read": False,
                        "timestamp": datetime.utcnow()
                    }
                    notifications_collection.insert_one(notification)
                    logger.info(f"📱 Created notification for user {user['email']}")
        
        logger.info(f"🎉 Job creation successful: {created_job['title']}")
        return created_job
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Job creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/jobs", response_model=List[JobResponse])
async def get_jobs(
    status: Optional[str] = None,
    location: Optional[str] = None,
    title: Optional[str] = None,  # Changed from category to title
    current_user: dict = Depends(get_current_user)
):
    # Build query
    query = {}
    if status:
        query["status"] = status
    if location:
        query["location"] = location
    if title:
        query["title"] = title
    
    # Get jobs
    jobs = list(jobs_collection.find(query))
    return [serialize_id(job) for job in jobs]

@app.get("/jobs/provider", response_model=List[JobResponse])
async def get_provider_jobs(
    current_user: dict = Depends(get_current_user)
):
    # Check if user is a provider
    if current_user["userType"] != "provider":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only job providers can access this endpoint"
        )
    
    # Get jobs
    jobs = list(jobs_collection.find({"providerId": current_user["id"]}))
    return [serialize_id(job) for job in jobs]

@app.get("/jobs/matching", response_model=List[JobResponse])
async def get_matching_jobs(
    current_user: dict = Depends(get_current_user)
):
    # Check if user is a seeker
    if current_user["userType"] != "seeker":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only job seekers can access this endpoint"
        )
    
    # Get all open jobs
    jobs = list(jobs_collection.find({"status": "open", "jobStatus": "OPEN"}))
    
    # Calculate match scores and sort
    job_matches = []
    for job in jobs:
        job = serialize_id(job)
        match_score = calculate_job_match_score(job, current_user)
        job["matchScore"] = match_score
        job_matches.append(job)
    
    # Sort by match score (descending)
    job_matches.sort(key=lambda x: x["matchScore"], reverse=True)
    
    return job_matches

@app.get("/jobs/search", response_model=List[JobResponse])

async def search_jobs(

    q: Optional[str] = None,

    location: Optional[str] = None,

    title: Optional[str] = None,

    wage_type: Optional[str] = None,

    negotiable: Optional[bool] = None,

    current_user: dict = Depends(get_current_user)

):

    try:

        logger.info(f"🔍 Search request - q: '{q}', location: '{location}', title: '{title}'")

        

        # Build search query - always include open jobs by default

        query = {"status": "open"}

        

        # Only filter by jobStatus if no search term is provided

        # This allows searching in all jobs regardless of status when a search term is provided

        if not q or not q.strip():

            query["jobStatus"] = "OPEN"

        

        if location and location != "all":

            query["location"] = {"$regex": location, "$options": "i"}

        if title and title != "all":

            query["title"] = {"$regex": title, "$options": "i"}

        if wage_type and wage_type != "all":

            query["wageType"] = wage_type

        if negotiable is not None:

            query["negotiable"] = negotiable

        

        # Enhanced text search with better partial matching

        if q and q.strip():

            search_term = q.strip()

            # Create case-insensitive regex pattern for partial matching

            regex_pattern = {"$regex": search_term, "$options": "i"}

            

            query["$or"] = [

                {"title": regex_pattern},

                {"description": regex_pattern},

                {"location": regex_pattern},

                {"providerName": regex_pattern},

                {"requiredSkills": {"$elemMatch": regex_pattern}},

                # Also search in payment and duration fields

                {"payment": regex_pattern},

                {"duration": regex_pattern}

            ]

            

            logger.info(f"🔍 Search query: '{search_term}' with regex pattern")

        

        logger.info(f"🔍 MongoDB query: {query}")

        

        # Get jobs

        jobs = list(jobs_collection.find(query))

        logger.info(f"🔍 Found {len(jobs)} jobs matching search criteria")

        

        # If user is a seeker, calculate match scores

        if current_user["userType"] == "seeker":

            job_matches = []

            for job in jobs:

                job = serialize_id(job)

                match_score = calculate_job_match_score(job, current_user)

                job["matchScore"] = match_score

                job_matches.append(job)

            

            # Sort by match score (descending) for better relevance

            job_matches.sort(key=lambda x: x["matchScore"], reverse=True)

            logger.info(f"🎯 Sorted {len(job_matches)} jobs by match score for seeker")

            return job_matches

        

        # For providers, sort by creation date (newest first)

        serialized_jobs = [serialize_id(job) for job in jobs]

        serialized_jobs.sort(key=lambda x: x.get("createdAt", datetime.min), reverse=True)

        

        return serialized_jobs

        

    except Exception as e:

        logger.error(f"❌ Search jobs error: {e}")

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Search failed: {str(e)}"

        )


@app.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: str,
    current_user: dict = Depends(get_current_user)
):
    # Get job
    job = jobs_collection.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    return serialize_id(job)

@app.post("/applications", response_model=ApplicationResponse)
async def create_application(
    application: ApplicationCreate,
    current_user: dict = Depends(get_current_user)
):
    # Check if user is a seeker
    if current_user["userType"] != "seeker":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only job seekers can apply for jobs"
        )
    
    # Check if job exists and is open
    job = jobs_collection.find_one({"_id": ObjectId(application.jobId)})
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    if job["status"] != "open":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Job is not open for applications"
        )
    
    # Check if already applied
    existing_application = applications_collection.find_one({
        "jobId": application.jobId,
        "seekerId": current_user["id"]
    })
    if existing_application:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You have already applied for this job"
        )
    
    # Create application
    application_dict = application.dict()
    application_dict["seekerId"] = current_user["id"]
    application_dict["seekerName"] = current_user["name"]
    application_dict["status"] = "pending"
    application_dict["appliedAt"] = datetime.utcnow()
    application_dict["seekerProfile"] = {
        "skills": current_user["skills"],
        "rating": current_user["rating"],
        "experience": current_user.get("bio", ""),
        "email": current_user["email"],  # Include actual email
        "phone": current_user["phone"],  # Include actual phone
        "name": current_user["name"],
        "age": current_user["age"],
        "gender": current_user["gender"],
        "workingCity": current_user["workingCity"],
        "yearsOfExperience": current_user.get("yearsOfExperience", 0)
    }
    
    # Insert into database
    result = applications_collection.insert_one(application_dict)
    
    # Update job applicants count
    jobs_collection.update_one(
        {"_id": ObjectId(application.jobId)},
        {"$inc": {"applicants": 1}}
    )
    
    # Get updated applicant count
    updated_job = jobs_collection.find_one({"_id": ObjectId(application.jobId)})
    applicant_count = updated_job["applicants"]
    
    # Get provider details
    provider = users_collection.find_one({"_id": ObjectId(job["providerId"])})
    
    # Send email notification to provider
    if provider:
        send_application_notification_email(
            provider["email"], 
            serialize_id(job),  # Pass the complete job object instead of just title
            applicant_count
        )
    
    # Create notification for job provider
    notification = {
        "userId": job["providerId"],
        "type": "new-application",
        "title": "New Application",
        "message": f"{current_user['name']} has applied for your job: {job['title']}. You now have {applicant_count} applicant(s).",
        "read": False,
        "timestamp": datetime.utcnow()
    }
    notifications_collection.insert_one(notification)
    
    # Return created application
    created_application = applications_collection.find_one({"_id": result.inserted_id})
    return serialize_id(created_application)

@app.get("/applications/job/{job_id}", response_model=List[ApplicationResponse])
async def get_job_applications(
    job_id: str,
    current_user: dict = Depends(get_current_user)
):
    # Check if job exists and user is the provider
    job = jobs_collection.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    if job["providerId"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view applications for your own jobs"
        )
    
    # Get applications
    applications = list(applications_collection.find({"jobId": job_id}))
    
    # Calculate ranking scores for each applicant and enrich with full user data
    ranked_applications = []
    for app in applications:
        app = serialize_id(app)
        
        # Get full seeker details from users collection
        seeker = users_collection.find_one({"_id": ObjectId(app["seekerId"])})
        if seeker:
            seeker = serialize_id(seeker)
            ranking_score = calculate_seeker_ranking_score(seeker, job)
            app["rankingScore"] = ranking_score
            
            # Update seekerProfile with complete information
            app["seekerProfile"] = {
                "skills": seeker.get("skills", []),
                "rating": seeker.get("rating", 0),
                "experience": seeker.get("bio", ""),
                "email": seeker.get("email", ""),
                "phone": seeker.get("phone", ""),
                "name": seeker.get("name", ""),
                "age": seeker.get("age", 0),
                "gender": seeker.get("gender", ""),
                "workingCity": seeker.get("workingCity", ""),
                "yearsOfExperience": seeker.get("yearsOfExperience", 0),
                "permanentAddress": seeker.get("permanentAddress", ""),
                "presentAddress": seeker.get("presentAddress", ""),
                "pincode": seeker.get("pincode", ""),
                "rankingScore": ranking_score
            }
        
        ranked_applications.append(app)
    
    # Sort by ranking score (descending)
    ranked_applications.sort(key=lambda x: x.get("rankingScore", 0), reverse=True)
    
    return ranked_applications

@app.get("/applications/seeker", response_model=List[ApplicationResponse])
async def get_seeker_applications(
    current_user: dict = Depends(get_current_user)
):
    # Check if user is a seeker
    if current_user["userType"] != "seeker":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only job seekers can access this endpoint"
        )
    
    # Get applications
    applications = list(applications_collection.find({"seekerId": current_user["id"]}))
    return [serialize_id(application) for application in applications]

@app.put("/applications/{application_id}/select", response_model=ApplicationResponse)
async def select_applicant(
    application_id: str,
    current_user: dict = Depends(get_current_user)
):
    # Check if user is a provider
    if current_user["userType"] != "provider":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only job providers can select applicants"
        )
    
    # Check if application exists
    application = applications_collection.find_one({"_id": ObjectId(application_id)})
    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )
    
    # Check if job exists and user is the provider
    job = jobs_collection.find_one({"_id": ObjectId(application["jobId"])})
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    if job["providerId"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only select applicants for your own jobs"
        )
    
    # Update application status
    applications_collection.update_one(
        {"_id": ObjectId(application_id)},
        {"$set": {"status": "selected"}}
    )
    
    # Reject other applications
    applications_collection.update_many(
        {
            "jobId": application["jobId"],
            "_id": {"$ne": ObjectId(application_id)}
        },
        {"$set": {"status": "rejected"}}
    )
    
    # Update job status
    jobs_collection.update_one(
        {"_id": ObjectId(application["jobId"])},
        {
            "$set": {
                "status": "assigned",
                "assignedTo": application["seekerId"]
            }
        }
    )
    
    # Get seeker details for email
    seeker = users_collection.find_one({"_id": ObjectId(application["seekerId"])})
    
    # Send email notification to selected seeker
    if seeker:
        send_selection_notification_email(
            seeker["email"], 
            job["title"], 
            current_user["name"]
        )
    
    # Create notification for selected seeker
    notification = {
        "userId": application["seekerId"],
        "type": "job-selected",
        "title": "Job Offer",
        "message": f"Congratulations! You've been selected for the job: {job['title']}",
        "read": False,
        "timestamp": datetime.utcnow()
    }
    notifications_collection.insert_one(notification)
    
    # Create notifications for rejected applicants
    rejected_applications = applications_collection.find({
        "jobId": application["jobId"],
        "_id": {"$ne": ObjectId(application_id)}
    })
    
    for rejected_app in rejected_applications:
        notification = {
            "userId": rejected_app["seekerId"],
            "type": "application-rejected",
            "title": "Application Update",
            "message": f"Thank you for your interest in {job['title']}. Unfortunately, another candidate was selected.",
            "read": False,
            "timestamp": datetime.utcnow()
        }
        notifications_collection.insert_one(notification)
    
    # Return updated application
    updated_application = applications_collection.find_one({"_id": ObjectId(application_id)})
    return serialize_id(updated_application)

@app.put("/jobs/{job_id}/complete", response_model=JobResponse)
async def complete_job(
    job_id: str,
    completion: JobCompletionRequest,
    current_user: dict = Depends(get_current_user)
):
    # Check if job exists
    job = jobs_collection.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    
    # Check if user is the provider or the assigned seeker
    if job["providerId"] != current_user["id"] and job["assignedTo"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only complete your own jobs or jobs assigned to you"
        )
    
    # Check if job is assigned
    if job["status"] != "assigned":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only assigned jobs can be completed"
        )
    
    # Update job status
    jobs_collection.update_one(
        {"_id": ObjectId(job_id)},
        {
            "$set": {
                "status": "completed",
                "completedAt": datetime.utcnow()
            }
        }
    )
    
    # Find the selected application
    application = applications_collection.find_one({
        "jobId": job_id,
        "status": "selected"
    })
    
    if application:
        # Update application with feedback
        applications_collection.update_one(
            {"_id": application["_id"]},
            {
                "$set": {
                    "feedback": {
                        "rating": completion.rating,
                        "comment": completion.feedback
                    }
                }
            }
        )
        
        # Get user details for email
        if current_user["userType"] == "provider":
            # Provider completing, notify seeker
            seeker = users_collection.find_one({"_id": ObjectId(job["assignedTo"])})
            if seeker:
                send_job_completion_email(
                    seeker["email"], 
                    job["title"], 
                    completion.rating, 
                    completion.feedback, 
                    False,
                    serialize_id(job)  # Pass job details
                )
            
            notification = {
                "userId": job["assignedTo"],
                "type": "job-completed",
                "title": "Job Completed",
                "message": f"You received a {completion.rating}-star rating for the job: {job['title']}. Feedback: {completion.feedback}",
                "read": False,
                "timestamp": datetime.utcnow()
            }
            notifications_collection.insert_one(notification)
            
            # Update seeker's rating
            seeker = users_collection.find_one({"_id": ObjectId(job["assignedTo"])})
            if seeker:
                # Calculate new average rating
                seeker_applications = list(applications_collection.find({
                    "seekerId": job["assignedTo"],
                    "feedback": {"$exists": True}
                }))
                
                total_ratings = sum(app["feedback"]["rating"] for app in seeker_applications if "feedback" in app)
                new_rating = total_ratings / len(seeker_applications)
                
                users_collection.update_one(
                    {"_id": ObjectId(job["assignedTo"])},
                    {"$set": {"rating": new_rating}}
                )
        else:
            # Seeker completing, notify provider
            provider = users_collection.find_one({"_id": ObjectId(job["providerId"])})
            if provider:
                send_job_completion_email(
                    provider["email"], 
                    job["title"], 
                    completion.rating, 
                    completion.feedback, 
                    True,
                    serialize_id(job)  # Pass job details
                )
            
            notification = {
                "userId": job["providerId"],
                "type": "job-completed",
                "title": "Job Completed",
                "message": f"You received a {completion.rating}-star rating for the job: {job['title']}. Feedback: {completion.feedback}",
                "read": False,
                "timestamp": datetime.utcnow()
            }
            notifications_collection.insert_one(notification)
            
            # Update provider's rating
            provider = users_collection.find_one({"_id": ObjectId(job["providerId"])})
            if provider:
                # Calculate new average rating
                provider_jobs = list(jobs_collection.find({
                    "providerId": job["providerId"],
                    "status": "completed"
                }))
                
                provider_applications = list(applications_collection.find({
                    "jobId": {"$in": [str(j["_id"]) for j in provider_jobs]},
                    "feedback": {"$exists": True}
                }))
                
                if provider_applications:
                    total_ratings = sum(app["feedback"]["rating"] for app in provider_applications if "feedback" in app)
                    new_rating = total_ratings / len(provider_applications)
                    
                    users_collection.update_one(
                        {"_id": ObjectId(job["providerId"])},
                        {"$set": {"rating": new_rating}}
                    )
    
    # Return updated job
    updated_job = jobs_collection.find_one({"_id": ObjectId(job_id)})
    return serialize_id(updated_job)

@app.get("/notifications", response_model=List[NotificationResponse])
async def get_notifications(
    current_user: dict = Depends(get_current_user)
):
    # Get notifications sorted by timestamp (newest first)
    notifications = list(notifications_collection.find({"userId": current_user["id"]}).sort("timestamp", -1))
    return [serialize_id(notification) for notification in notifications]

@app.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    # Check if notification exists and belongs to user
    notification = notifications_collection.find_one({"_id": ObjectId(notification_id)})
    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found"
        )
    if notification["userId"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only mark your own notifications as read"
        )
    
    # Mark notification as read
    notifications_collection.update_one(
        {"_id": ObjectId(notification_id)},
        {"$set": {"read": True}}
    )
    
    return {"message": "Notification marked as read"}

@app.put("/notifications/read-all")
async def mark_all_notifications_read(
    current_user: dict = Depends(get_current_user)
):
    # Mark all notifications as read
    notifications_collection.update_many(
        {"userId": current_user["id"]},
        {"$set": {"read": True}}
    )
    
    return {"message": "All notifications marked as read"}

# Enhance the search_jobs endpoint to improve search functionality
@app.get("/jobs/search", response_model=List[JobResponse])
async def search_jobs(
    q: Optional[str] = None,
    location: Optional[str] = None,
    title: Optional[str] = None,
    wage_type: Optional[str] = None,
    negotiable: Optional[bool] = None,
    current_user: dict = Depends(get_current_user)
):
    try:
        logger.info(f"🔍 Search request - q: '{q}', location: '{location}', title: '{title}'")
        
        # Build search query - always include open jobs by default
        query = {"status": "open"}
        
        # Only filter by jobStatus if no search term is provided
        # This allows searching in all jobs regardless of status when a search term is provided
        if not q or not q.strip():
            query["jobStatus"] = "OPEN"
        
        if location and location != "all":
            query["location"] = {"$regex": location, "$options": "i"}
        if title and title != "all":
            query["title"] = {"$regex": title, "$options": "i"}
        if wage_type and wage_type != "all":
            query["wageType"] = wage_type
        if negotiable is not None:
            query["negotiable"] = negotiable
        
        # Enhanced text search with better partial matching
        if q and q.strip():
            search_term = q.strip()
            # Create case-insensitive regex pattern for partial matching
            regex_pattern = {"$regex": search_term, "$options": "i"}
            
            query["$or"] = [
                {"title": regex_pattern},
                {"description": regex_pattern},
                {"location": regex_pattern},
                {"providerName": regex_pattern},
                {"requiredSkills": {"$elemMatch": regex_pattern}},
                # Also search in payment and duration fields
                {"payment": regex_pattern},
                {"duration": regex_pattern}
            ]
            
            logger.info(f"🔍 Search query: '{search_term}' with regex pattern")
        
        logger.info(f"🔍 MongoDB query: {query}")
        
        # Get jobs
        jobs = list(jobs_collection.find(query))
        logger.info(f"🔍 Found {len(jobs)} jobs matching search criteria")
        
        # If user is a seeker, calculate match scores
        if current_user["userType"] == "seeker":
            job_matches = []
            for job in jobs:
                job = serialize_id(job)
                match_score = calculate_job_match_score(job, current_user)
                job["matchScore"] = match_score
                job_matches.append(job)
            
            # Sort by match score (descending) for better relevance
            job_matches.sort(key=lambda x: x["matchScore"], reverse=True)
            logger.info(f"🎯 Sorted {len(job_matches)} jobs by match score for seeker")
            return job_matches
        
        # For providers, sort by creation date (newest first)
        serialized_jobs = [serialize_id(job) for job in jobs]
        serialized_jobs.sort(key=lambda x: x.get("createdAt", datetime.min), reverse=True)
        
        return serialized_jobs
        
    except Exception as e:
        logger.error(f"❌ Search jobs error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )

@app.get("/jobs/all", response_model=List[JobResponse])
async def get_all_open_jobs(current_user: dict = Depends(get_current_user)):
    """Get all open jobs - simplified endpoint for debugging"""
    try:
        logger.info("📋 Fetching all open jobs")
        
        # Simple query for open jobs
        query = {
            "status": "open",
            "$or": [
                {"jobStatus": "OPEN"},
                {"jobStatus": {"$exists": False}}
            ]
        }
        
        jobs = list(jobs_collection.find(query))
        logger.info(f"📋 Found {len(jobs)} open jobs")
        
        serialized_jobs = [serialize_id(job) for job in jobs]
        
        # Sort by creation date (newest first)
        serialized_jobs.sort(key=lambda x: x.get("createdAt", datetime.min), reverse=True)
        
        return serialized_jobs
        
    except Exception as e:
        logger.error(f"❌ Get all jobs error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch jobs: {str(e)}"
        )

# Payment endpoints
@app.post("/payments", response_model=PaymentResponse)
async def create_payment(
    payment: PaymentCreate,
    current_user: dict = Depends(get_current_user)
):
    # Check if user is a provider
    if current_user["userType"] != "provider":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only job providers can make payments"
        )
    
    # Create payment record
    payment_dict = payment.dict()
    payment_dict["providerId"] = current_user["id"]
    payment_dict["status"] = "completed"  # Dummy payment always succeeds
    payment_dict["createdAt"] = datetime.utcnow()
    
    # Insert into database
    result = payments_collection.insert_one(payment_dict)
    
    # Return created payment
    created_payment = payments_collection.find_one({"_id": result.inserted_id})
    return serialize_id(created_payment)

@app.get("/payments/job/{job_id}")
async def check_payment_status(
    job_id: str,
    current_user: dict = Depends(get_current_user)
):
    # Check if payment exists for this job and provider
    payment = payments_collection.find_one({
        "jobId": job_id,
        "providerId": current_user["id"],
        "status": "completed"
    })
    
    return {"hasPaid": payment is not None}

# Admin endpoints
@app.get("/admin/users")
async def get_all_users():
    try:
        # Get all users with additional computed fields
        users = list(users_collection.find({}))
        
        # Add computed fields for each user
        for user in users:
            user = serialize_id(user)
            
            # Count applications for seekers
            if user.get("userType") == "seeker":
                user["applicationCount"] = applications_collection.count_documents({"seekerId": user["id"]})
            
            # Count jobs for providers
            if user.get("userType") == "provider":
                user["jobCount"] = jobs_collection.count_documents({"providerId": user["id"]})
        
        return [serialize_id(user) for user in users]
    except Exception as e:
        logger.error(f"❌ Admin get users error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users data"
        )

@app.get("/admin/jobs")
async def get_all_jobs():
    try:
        # Get all jobs with additional computed fields
        jobs = list(jobs_collection.find({}))
        
        # Add computed fields for each job
        for job in jobs:
            job = serialize_id(job)
            
            # Count applications for each job
            job["applicationCount"] = applications_collection.count_documents({"jobId": job["id"]})
            
            # Get provider details
            provider = users_collection.find_one({"_id": ObjectId(job["providerId"])})
            if provider:
                job["providerEmail"] = provider.get("email", "")
                job["providerPhone"] = provider.get("phone", "")
        
        return [serialize_id(job) for job in jobs]
    except Exception as e:
        logger.error(f"❌ Admin get jobs error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch jobs data"
        )

@app.get("/admin/stats")
async def get_admin_stats():
    try:
        # Get comprehensive statistics
        total_users = users_collection.count_documents({})
        total_jobs = jobs_collection.count_documents({})
        total_applications = applications_collection.count_documents({})
        active_jobs = jobs_collection.count_documents({"status": "open"})
        
        # Additional statistics
        total_seekers = users_collection.count_documents({"userType": "seeker"})
        total_providers = users_collection.count_documents({"userType": "provider"})
        completed_jobs = jobs_collection.count_documents({"status": "completed"})
        assigned_jobs = jobs_collection.count_documents({"status": "assigned"})
        
        # Recent activity counts (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_users = users_collection.count_documents({"createdAt": {"$gte": seven_days_ago}})
        recent_jobs = jobs_collection.count_documents({"createdAt": {"$gte": seven_days_ago}})
        
        return {
            "totalUsers": total_users,
            "totalJobs": total_jobs,
            "totalApplications": total_applications,
            "activeJobs": active_jobs,
            "totalSeekers": total_seekers,
            "totalProviders": total_providers,
            "completedJobs": completed_jobs,
            "assignedJobs": assigned_jobs,
            "recentUsers": recent_users,
            "recentJobs": recent_jobs,
            "lastUpdated": datetime.utcnow()
        }
    except Exception as e:
        logger.error(f"❌ Admin get stats error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch statistics"
        )

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str):
    try:
        # Check if user exists
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Delete user and related data
        result = users_collection.delete_one({"_id": ObjectId(user_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Clean up related data
        if user.get("userType") == "seeker":
            # Delete applications
            applications_collection.delete_many({"seekerId": user_id})
        elif user.get("userType") == "provider":
            # Delete jobs and their applications
            job_ids = [str(job["_id"]) for job in jobs_collection.find({"providerId": user_id})]
            jobs_collection.delete_many({"providerId": user_id})
            applications_collection.delete_many({"jobId": {"$in": job_ids}})
        
        # Delete notifications
        notifications_collection.delete_many({"userId": user_id})
        
        logger.info(f"🗑️ Admin deleted user: {user_id}")
        return {"message": "User and related data deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Admin delete user error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )

@app.delete("/admin/jobs/{job_id}")
async def delete_job(job_id: str):
    try:
        # Check if job exists
        job = jobs_collection.find_one({"_id": ObjectId(job_id)})
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found"
            )
        
        # Delete job and related data
        result = jobs_collection.delete_one({"_id": ObjectId(job_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found"
            )
        
        # Delete related applications
        applications_collection.delete_many({"jobId": job_id})
        
        # Delete related notifications
        notifications_collection.delete_many({
            "message": {"$regex": job.get("title", ""), "$options": "i"}
        })
        
        logger.info(f"🗑️ Admin deleted job: {job_id}")
        return {"message": "Job and related data deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Admin delete job error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete job"
        )

# New endpoint for recent activity
@app.get("/admin/activity")
async def get_recent_activity():
    try:
        activities = []
        
        # Get recent users (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_users = list(users_collection.find(
            {"createdAt": {"$gte": thirty_days_ago}}
        ).sort("createdAt", -1).limit(20))
        
        for user in recent_users:
            activities.append({
                "type": "user_registration",
                "message": f"New user registration: {user['name']} ({user['userType']})",
                "timestamp": user["createdAt"],
                "userId": str(user["_id"]),
                "userType": user["userType"]
            })
        
        # Get recent jobs (last 30 days)
        recent_jobs = list(jobs_collection.find(
            {"createdAt": {"$gte": thirty_days_ago}}
        ).sort("createdAt", -1).limit(20))
        
        for job in recent_jobs:
            activities.append({
                "type": "job_posting",
                "message": f"Job posted: {job['title']} by {job['providerName']}",
                "timestamp": job["createdAt"],
                "jobId": str(job["_id"]),
                "providerId": job["providerId"]
            })
        
        # Sort all activities by timestamp (newest first)
        activities.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return activities[:50]  # Return last 50 activities
        
    except Exception as e:
        logger.error(f"❌ Admin get activity error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch recent activity"
        )

# Admin authentication endpoint
@app.post("/admin/login")
async def admin_login(credentials: dict):
    try:
        username = credentials.get("username")
        password = credentials.get("password")
        
        # Simple admin authentication (in production, use proper authentication)
        if username == "admin" and password == "admin123":
            admin_token = create_access_token(
                data={"sub": "admin", "role": "admin"}, 
                expires_delta=timedelta(hours=8)
            )
            return {"access_token": admin_token, "token_type": "bearer", "role": "admin"}
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin credentials"
            )
    except Exception as e:
        logger.error(f"❌ Admin login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin login failed"
        )

# Admin notification endpoints
@app.get("/admin/notifications")
async def get_all_notifications():
    try:
        # Get all notifications with user details
        notifications = list(notifications_collection.find({}).sort("timestamp", -1))
        
        # Enrich notifications with user details
        enriched_notifications = []
        for notification in notifications:
            notification = serialize_id(notification)
            
            # Get user details
            user = users_collection.find_one({"_id": ObjectId(notification["userId"])})
            if user:
                notification["userName"] = user.get("name", "Unknown User")
                notification["userEmail"] = user.get("email", "")
                notification["userType"] = user.get("userType", "")
            else:
                notification["userName"] = "Deleted User"
                notification["userEmail"] = ""
                notification["userType"] = ""
            
            # Add additional context based on notification type
            if notification["type"] == "new-application":
                # Try to extract job title from message
                message = notification.get("message", "")
                if "job:" in message:
                    job_title = message.split("job:")[-1].split(".")[0].strip()
                    notification["jobTitle"] = job_title
            elif notification["type"] == "job-selected":
                # Extract job title from message
                message = notification.get("message", "")
                if "job:" in message:
                    job_title = message.split("job:")[-1].strip()
                    notification["jobTitle"] = job_title
            
            enriched_notifications.append(notification)
        
        return enriched_notifications
        
    except Exception as e:
        logger.error(f"❌ Admin get notifications error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch notifications data"
        )

@app.get("/admin/notifications/stats")
async def get_notification_stats():
    try:
        # Get notification statistics
        total_notifications = notifications_collection.count_documents({})
        unread_notifications = notifications_collection.count_documents({"read": False})
        
        # Get notifications by type
        notification_types = notifications_collection.aggregate([
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ])
        
        type_stats = {item["_id"]: item["count"] for item in notification_types}
        
        # Get recent activity (last 24 hours)
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        recent_notifications = notifications_collection.count_documents({
            "timestamp": {"$gte": twenty_four_hours_ago}
        })
        
        return {
            "totalNotifications": total_notifications,
            "unreadNotifications": unread_notifications,
            "recentNotifications": recent_notifications,
            "notificationTypes": type_stats,
            "lastUpdated": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"❌ Admin get notification stats error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch notification statistics"
        )

@app.delete("/admin/notifications/{notification_id}")
async def delete_notification(notification_id: str):
    try:
        # Check if notification exists
        notification = notifications_collection.find_one({"_id": ObjectId(notification_id)})
        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
        # Delete notification
        result = notifications_collection.delete_one({"_id": ObjectId(notification_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
        logger.info(f"🗑️ Admin deleted notification: {notification_id}")
        return {"message": "Notification deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Admin delete notification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete notification"
        )

@app.put("/admin/notifications/mark-all-read")
async def mark_all_notifications_read_admin():
    try:
        # Mark all notifications as read
        result = notifications_collection.update_many(
            {"read": False},
            {"$set": {"read": True}}
        )
        
        logger.info(f"📱 Admin marked {result.modified_count} notifications as read")
        return {
            "message": f"Marked {result.modified_count} notifications as read",
            "modifiedCount": result.modified_count
        }
        
    except Exception as e:
        logger.error(f"❌ Admin mark all notifications read error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to mark notifications as read"
        )

# Seed data if database is empty
@app.post("/seed", status_code=status.HTTP_201_CREATED)
async def seed_data():
    # Check if database is empty
    if users_collection.count_documents({}) > 0:
        return {"message": "Database already contains data"}
    
    # Seed users
    users = [
        {
            "name": "Farmer John",
            "email": "john@village.com",
            "userType": "provider",
            "location": "North Village",
            "phone": "123-456-7890",
            "rating": 4.8,
            "bio": "I own a large farm and often need help with harvesting and maintenance.",
            "createdAt": datetime.utcnow(),
            "gender": "male",
            "age": 55,
            "permanentAddress": "123 Farm Rd, North Village",
            "presentAddress": "123 Farm Rd, North Village",
            "workingCity": "North Village",
            "pincode": "123456",
            "yearsOfExperience": 20,
            "skills": []
        },
        {
            "name": "Mary Worker",
            "email": "mary@village.com",
            "userType": "seeker",
            "location": "North Village",
            "phone": "123-456-7891",
            "rating": 4.5,
            "bio": "Experienced in farm work and construction. Looking for daily wage jobs.",
            "createdAt": datetime.utcnow(),
            "gender": "female",
            "age": 32,
            "permanentAddress": "456 Worker St, North Village",
            "presentAddress": "456 Worker St, North Village",
            "workingCity": "North Village",
            "pincode": "123456",
            "yearsOfExperience": 8,
            "skills": ["farming", "construction", "cleaning"]
        }
    ]
    
    users_collection.insert_many(users)
    
    return {"message": "Database seeded successfully"}

# Development endpoint for OTP retrieval (only in development)
@app.get("/dev/get-otp/{email}")
async def get_otp_for_testing(email: str):
    """Development endpoint to get OTP for testing - only available in development"""
    if ENVIRONMENT == "production":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not available in production"
        )
    
    # Find the latest OTP for this email
    otp_data = otp_collection.find_one(
        {"email": email, "expiresAt": {"$gt": datetime.utcnow()}},
        sort=[("createdAt", -1)]
    )
    
    if otp_data:
        return {
            "email": email,
            "otp": otp_data["otp"],
            "expiresAt": otp_data["expiresAt"],
            "timeRemaining": (otp_data["expiresAt"] - datetime.utcnow()).total_seconds()
        }
    else:
        return {"message": "No valid OTP found for this email"}

@app.post("/verify-otp-registration")
async def verify_otp_registration(request: dict):
    """Verify OTP for registration without consuming it"""
    try:
        email = request.get("email")
        otp = request.get("otp")
        verify_only = request.get("verify_only", False)
        
        logger.info(f"🔐 OTP verification for registration: {email} (verify_only: {verify_only})")
        
        # Find OTP
        otp_data = otp_collection.find_one({
            "email": email,
            "otp": otp,
            "type": "registration",
            "expiresAt": {"$gt": datetime.utcnow()}
        })
        
        if not otp_data:
            logger.warning(f"⚠️ Invalid or expired registration OTP for: {email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        # If verify_only is True, don't consume the OTP
        if not verify_only:
            # Delete the used OTP
            otp_collection.delete_one({"_id": otp_data["_id"]})
            logger.info(f"🗑️ Registration OTP consumed for: {email}")
        else:
            logger.info(f"✅ Registration OTP verified (not consumed) for: {email}")
        
        return {
            "message": "OTP verified successfully",
            "email": email,
            "expires_at": otp_data["expiresAt"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ OTP verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    logger.info("🚀 Starting Workers Globe API server...")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
