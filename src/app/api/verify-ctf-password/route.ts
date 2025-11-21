import { NextResponse, NextRequest } from 'next/server';
import { CTFWriteupsDB } from '@/lib/db';
import { emailService } from '@/lib/email-service';

export async function POST(request: NextRequest) {
  try {
    const { writeupId, password, email, name, otp, step, verificationToken } = await request.json();

    if (!writeupId || !password) {
      return NextResponse.json(
        { error: 'Writeup ID and password are required' },
        { status: 400 }
      );
    }

    const writeupsDB = new CTFWriteupsDB();
    const writeup = await writeupsDB.getWriteup(writeupId);

    if (!writeup) {
      return NextResponse.json(
        { error: 'Writeup not found' },
        { status: 404 }
      );
    }

    if (!writeup.is_active || !writeup.password) {
      return NextResponse.json(
        { error: 'This writeup does not require password verification' },
        { status: 400 }
      );
    }

    if (password !== writeup.password) {
      return NextResponse.json(
        { error: 'Invalid password' },
        { status: 401 }
      );
    }

    // If only password verification step, return success with a verification token
    if (step === 'password') {
      // Generate a temporary verification token
      const verificationToken = Buffer.from(`${writeupId}:${password}:${Date.now()}`).toString('base64');
      
      return NextResponse.json({
        success: true,
        message: 'Password verified',
        verificationToken
      });
    }

    // For complete step, require email, OTP, and verification token
    if (step === 'complete') {
      if (!email || !otp) {
        return NextResponse.json(
          { error: 'Email and OTP are required for access' },
          { status: 400 }
        );
      }
      
      // Verify the password again for complete step (prevent bypass)
      if (password !== writeup.password) {
        return NextResponse.json(
          { error: 'Invalid password' },
          { status: 401 }
        );
      }
      
      // Validate verification token if provided
      if (verificationToken) {
        try {
          const decoded = Buffer.from(verificationToken, 'base64').toString();
          const [tokenWriteupId, tokenPassword] = decoded.split(':');
          
          if (tokenWriteupId !== writeupId || tokenPassword !== password) {
            return NextResponse.json(
              { error: 'Invalid verification token' },
              { status: 401 }
            );
          }
        } catch (error) {
          return NextResponse.json(
            { error: 'Invalid verification token format' },
            { status: 401 }
          );
        }
      }

      // Verify OTP
      try {
        const otpResponse = await fetch(`${request.nextUrl.origin}/api/verify-otp`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            email,
            otp,
            machineId: writeupId,
            name
          })
        });

        const otpData = await otpResponse.json();
        
        if (!otpResponse.ok || !otpData.success) {
          return NextResponse.json(
            { error: otpData.error || 'Invalid OTP' },
            { status: 401 }
          );
        }
      } catch (error) {
        console.error('Error verifying OTP:', error);
        return NextResponse.json(
          { error: 'Failed to verify OTP' },
          { status: 500 }
        );
      }
    }

    // Log access attempt
    if (step === 'complete') {
      try {
        const clientIP = request.headers.get('x-forwarded-for') || 
                        request.headers.get('x-real-ip') || 
                        'unknown';
        
        // Send email notification about writeup access
        if (email) {
          emailService.sendWriteupAccessNotification(
            writeup.title,
            writeup.ctf_name,
            email,
            name || 'Anonymous',
            clientIP
          ).catch((err: any) => {
            console.error('Failed to send writeup access notification:', err);
          });
        }
      } catch (error) {
        console.error('Error logging writeup access:', error);
      }
    }

    return NextResponse.json({
      success: true,
      message: 'Password verified successfully',
      writeup: {
        id: writeup.id,
        title: writeup.title,
        slug: writeup.slug,
        ctfName: writeup.ctf_name,
        category: writeup.category,
        difficulty: writeup.difficulty,
        points: writeup.points,
        status: writeup.status,
        isActive: Boolean(writeup.is_active),
        dateCompleted: writeup.date_completed,
        tags: writeup.tags ? (typeof writeup.tags === 'string' ? JSON.parse(writeup.tags) : writeup.tags) : [],
        writeup: writeup.writeup,
        summary: writeup.summary,
        flag: writeup.flag
      }
    });

  } catch (error) {
    console.error('Error verifying CTF password:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}