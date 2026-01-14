import React, { useState } from 'react';
import { signup, checkUsernameAvailability, checkEmailAvailability } from '../../util/APIUtils';
import './Signup.css';
import { Link } from 'react-router-dom';
import { 
    NAME_MIN_LENGTH, NAME_MAX_LENGTH, 
    USERNAME_MIN_LENGTH, USERNAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH
} from '../../constants';

import { Form, Input, Button, notification, Icon, Progress } from 'antd';

const FormItem = Form.Item;

const Signup = (props) => {
    // 1. State Management
    const [name, setName] = useState({ value: '', validateStatus: null, errorMsg: null });
    const [username, setUsername] = useState({ value: '', validateStatus: null, errorMsg: null });
    const [email, setEmail] = useState({ value: '', validateStatus: null, errorMsg: null });
    const [password, setPassword] = useState({ value: '', validateStatus: null, errorMsg: null });
    const [isLoading, setIsLoading] = useState(false);

    // 2. Validation Functions
    const validateName = (nameValue) => {
        if(nameValue.length < NAME_MIN_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Name is too short (Minimum ${NAME_MIN_LENGTH} characters needed.)` };
        } else if (nameValue.length > NAME_MAX_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Name is too long (Maximum ${NAME_MAX_LENGTH} characters allowed.)` };
        }
        return { validateStatus: 'success', errorMsg: null };
    };

    const validateEmail = (emailValue) => {
        if(!emailValue) {
            return { validateStatus: 'error', errorMsg: 'Email may not be empty' };
        }
        const EMAIL_REGEX = RegExp('[^@ ]+@[^@ ]+\\.[^@ ]+');
        if(!EMAIL_REGEX.test(emailValue)) {
            return { validateStatus: 'error', errorMsg: 'Email not valid' };
        }
        if(emailValue.length > EMAIL_MAX_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Email is too long (Max ${EMAIL_MAX_LENGTH} chars)` };
        }
        return { validateStatus: null, errorMsg: null };
    };

    const validateUsername = (usernameValue) => {
        if(usernameValue.length < USERNAME_MIN_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Too short (Min ${USERNAME_MIN_LENGTH} chars)` };
        } else if (usernameValue.length > USERNAME_MAX_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Too long (Max ${USERNAME_MAX_LENGTH} chars)` };
        }
        return { validateStatus: null, errorMsg: null };
    };

    const validatePassword = (passwordValue) => {
        if(passwordValue.length < PASSWORD_MIN_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Too short (Min ${PASSWORD_MIN_LENGTH} chars)` };
        } else if (passwordValue.length > PASSWORD_MAX_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Too long (Max ${PASSWORD_MAX_LENGTH} chars)` };
        }
        return { validateStatus: 'success', errorMsg: null };
    };

    // 3. Async Availability Checks
    const validateUsernameAvailability = async () => {
        const usernameValue = username.value;
        const validation = validateUsername(usernameValue);

        if(validation.validateStatus === 'error') {
            setUsername({ ...username, ...validation });
            return;
        }

        setUsername({ value: usernameValue, validateStatus: 'validating', errorMsg: null });

        try {
            const response = await checkUsernameAvailability(usernameValue);
            if(response.available) {
                setUsername({ value: usernameValue, validateStatus: 'success', errorMsg: null });
            } else {
                setUsername({ value: usernameValue, validateStatus: 'error', errorMsg: 'Username already taken' });
            }
        } catch(error) {
            setUsername({ value: usernameValue, validateStatus: 'success', errorMsg: null });
        }
    };

    const validateEmailAvailability = async () => {
        const emailValue = email.value;
        const validation = validateEmail(emailValue);

        if(validation.validateStatus === 'error') {
            setEmail({ ...email, ...validation });
            return;
        }

        setEmail({ value: emailValue, validateStatus: 'validating', errorMsg: null });

        try {
            const response = await checkEmailAvailability(emailValue);
            if(response.available) {
                setEmail({ value: emailValue, validateStatus: 'success', errorMsg: null });
            } else {
                setEmail({ value: emailValue, validateStatus: 'error', errorMsg: 'Email already registered' });
            }
        } catch(error) {
            setEmail({ value: emailValue, validateStatus: 'success', errorMsg: null });
        }
    };

    // 4. Input Handler
    const handleInputChange = (event, validationFun, setStateFun) => {
        const target = event.target;
        const inputValue = target.value;
        setStateFun({
            value: inputValue,
            ...validationFun(inputValue)
        });
    };

    // 5. Submit Handler
    const handleSubmit = (event) => {
        event.preventDefault();
        
        const signupRequest = {
            name: name.value,
            email: email.value,
            username: username.value,
            password: password.value
        };

        setIsLoading(true);

        signup(signupRequest)
        .then(response => {
            notification.success({
                message: 'Polling App',
                description: "Thank you! You're successfully registered. Please Login to continue!",
            });
            props.history.push("/login");
            setIsLoading(false);
        }).catch(error => {
            notification.error({
                message: 'Polling App',
                description: error.message || 'Sorry! Something went wrong. Please try again!'
            });
            setIsLoading(false);
        });
    };

    const isFormInvalid = () => {
        return !(name.validateStatus === 'success' &&
                 username.validateStatus === 'success' &&
                 email.validateStatus === 'success' &&
                 password.validateStatus === 'success');
    };

    // Feature: Calculate Password Strength (Simple)
    const getPasswordStrength = () => {
        const len = password.value.length;
        if (len === 0) return 0;
        if (len < 6) return 30;
        if (len < 10) return 70;
        return 100;
    };
    
    const getPasswordColor = () => {
        const len = password.value.length;
        if (len < 6) return '#ff4d4f'; // Red
        if (len < 10) return '#faad14'; // Orange
        return '#52c41a'; // Green
    };

    return (
        <div className="signup-container">
            <h1 className="page-title">Create Account</h1>
            <div className="signup-content">
                <Form onSubmit={handleSubmit} className="signup-form">
                    <FormItem 
                        label="Full Name"
                        validateStatus={name.validateStatus}
                        help={name.errorMsg}>
                        <Input 
                            size="large"
                            name="name"
                            autoComplete="off"
                            prefix={<Icon type="idcard" style={{ color: 'rgba(0,0,0,.25)' }} />}
                            placeholder="Your full name"
                            value={name.value} 
                            onChange={(e) => handleInputChange(e, validateName, setName)} />    
                    </FormItem>

                    <FormItem label="Username"
                        hasFeedback
                        validateStatus={username.validateStatus}
                        help={username.errorMsg}>
                        <Input 
                            size="large"
                            name="username" 
                            autoComplete="off"
                            prefix={<Icon type="user" style={{ color: 'rgba(0,0,0,.25)' }} />}
                            placeholder="A unique username"
                            value={username.value} 
                            onBlur={validateUsernameAvailability}
                            onChange={(e) => handleInputChange(e, validateUsername, setUsername)} />    
                    </FormItem>

                    <FormItem 
                        label="Email"
                        hasFeedback
                        validateStatus={email.validateStatus}
                        help={email.errorMsg}>
                        <Input 
                            size="large"
                            name="email" 
                            type="email" 
                            autoComplete="off"
                            prefix={<Icon type="mail" style={{ color: 'rgba(0,0,0,.25)' }} />}
                            placeholder="Your email"
                            value={email.value} 
                            onBlur={validateEmailAvailability}
                            onChange={(e) => handleInputChange(e, validateEmail, setEmail)} />    
                    </FormItem>

                    <FormItem 
                        label="Password"
                        validateStatus={password.validateStatus}
                        help={password.errorMsg}>
                        <Input 
                            size="large"
                            name="password" 
                            type="password"
                            autoComplete="off"
                            prefix={<Icon type="lock" style={{ color: 'rgba(0,0,0,.25)' }} />}
                            placeholder="A strong password" 
                            value={password.value} 
                            onChange={(e) => handleInputChange(e, validatePassword, setPassword)} />
                        
                        {/* Feature: Password Strength Meter */}
                        {password.value.length > 0 && (
                            <div style={{ marginTop: '5px' }}>
                                <Progress 
                                    percent={getPasswordStrength()} 
                                    showInfo={false} 
                                    strokeColor={getPasswordColor()} 
                                    size="small"
                                    style={{ lineHeight: 1 }}
                                />
                                <span style={{ fontSize: '12px', color: '#999' }}>Strength</span>
                            </div>
                        )}
                    </FormItem>

                    <FormItem>
                        <Button type="primary" 
                            htmlType="submit" 
                            size="large" 
                            className="signup-form-button"
                            loading={isLoading}
                            disabled={isFormInvalid() || isLoading}>Sign Up</Button>
                        <div className="login-link">
                            Already have an account? <Link to="/login">Login here!</Link>
                        </div>
                    </FormItem>
                </Form>
            </div>
        </div>
    );
};

export default Signup;