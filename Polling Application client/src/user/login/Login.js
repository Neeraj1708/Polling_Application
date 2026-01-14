import React, { useState } from 'react';
import { login } from '../../util/APIUtils';
import './Login.css';
import { Link } from 'react-router-dom';
import { ACCESS_TOKEN } from '../../constants';
import { Form, Input, Button, Icon, notification, Checkbox } from 'antd';

const Login = (props) => {
    return (
        <div className="login-container">
            <div className="login-content">
                <h1 className="page-title">Welcome Back</h1>
                <div className="login-illustration">
                    <Icon type="user" style={{ fontSize: '64px', color: '#722ed1' }} />
                </div>
                <LoginForm onLogin={props.onLogin} />
            </div>
        </div>
    );
}

const LoginForm = (props) => {
    // 1. State Management
    const [usernameOrEmail, setUsernameOrEmail] = useState({ value: '', validateStatus: 'success', errorMsg: null });
    const [password, setPassword] = useState({ value: '', validateStatus: 'success', errorMsg: null });
    const [loading, setLoading] = useState(false);

    // 2. Handlers
    const handleInputChange = (event, validationFun) => {
        const target = event.target;
        const inputName = target.name;
        const inputValue = target.value;

        if (inputName === 'usernameOrEmail') {
            setUsernameOrEmail({
                value: inputValue,
                ...validateInput(inputValue)
            });
        } else if (inputName === 'password') {
            setPassword({
                value: inputValue,
                ...validateInput(inputValue)
            });
        }
    };

    const validateInput = (input) => {
        if(input.length === 0) {
            return { validateStatus: 'error', errorMsg: null };
        }
        return { validateStatus: 'success', errorMsg: null };
    }

    const handleSubmit = (event) => {
        event.preventDefault();

        // Basic Validation
        if(usernameOrEmail.value.length === 0 || password.value.length === 0) {
             notification.error({
                message: 'Polling App',
                description: 'Please fill in all fields.'
            });
            return;
        }

        setLoading(true);

        const loginRequest = {
            usernameOrEmail: usernameOrEmail.value,
            password: password.value
        };

        login(loginRequest)
            .then(response => {
                localStorage.setItem(ACCESS_TOKEN, response.accessToken);
                props.onLogin();
                setLoading(false);
            })
            .catch(error => {
                setLoading(false);
                if (error.status === 401) {
                    notification.error({
                        message: 'Polling App',
                        description: 'Incorrect username or password. Please try again!'
                    });
                } else {
                    notification.error({
                        message: 'Polling App',
                        description: error.message || 'Sorry! Something went wrong. Please try again!'
                    });
                }
            });
    };

    return (
        <Form onSubmit={handleSubmit} className="login-form">
            <Form.Item 
                validateStatus={usernameOrEmail.validateStatus}
                help={usernameOrEmail.errorMsg}
                hasFeedback
            >
                <Input
                    prefix={<Icon type="user" style={{ color: 'rgba(0,0,0,.25)' }} />}
                    size="large"
                    name="usernameOrEmail"
                    value={usernameOrEmail.value}
                    onChange={(event) => handleInputChange(event, validateInput)}
                    placeholder="Username or Email"
                />
            </Form.Item>
            
            <Form.Item 
                validateStatus={password.validateStatus}
                help={password.errorMsg}
                hasFeedback
            >
                <Input
                    prefix={<Icon type="lock" style={{ color: 'rgba(0,0,0,.25)' }} />}
                    size="large"
                    name="password"
                    type="password"
                    value={password.value}
                    onChange={(event) => handleInputChange(event, validateInput)}
                    placeholder="Password"
                />
            </Form.Item>

            {/* Feature: Remember Me & Forgot Password */}
            <Form.Item className="remember-forgot-row">
                <Checkbox style={{float: 'left'}}>Remember me</Checkbox>
                <a className="login-form-forgot" href="#!" style={{float: 'right'}}>
                    Forgot password?
                </a>
            </Form.Item>

            <Form.Item style={{marginBottom: 0}}>
                <Button 
                    type="primary" 
                    htmlType="submit" 
                    size="large" 
                    className="login-form-button"
                    loading={loading}
                    block
                >
                    Log in
                </Button>
                
                <div style={{ marginTop: '15px', textAlign: 'center' }}>
                    Or <Link to="/signup">register now!</Link>
                </div>
            </Form.Item>
        </Form>
    );
}

export default Login;