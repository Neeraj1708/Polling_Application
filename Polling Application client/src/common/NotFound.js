import React from 'react';
import './NotFound.css';
import { Link } from 'react-router-dom';
import { Button, Icon } from 'antd';

const NotFound = () => {
    return (
        <div className="page-not-found">
            <div className="not-found-content">
                {/* 1. Animated Illustration */}
                <div className="illustration-container">
                    <Icon type="frown" className="not-found-icon" />
                    <div className="shadow"></div>
                </div>

                {/* 2. Gradient Title */}
                <h1 className="title">
                    404
                </h1>
                
                <div className="desc">
                    Oops! The page you're looking for doesn't exist.
                </div>
                
                {/* 3. Action Buttons */}
                <div className="action-buttons">
                    <Link to="/">
                        <Button className="go-back-btn" type="primary" size="large" icon="home">
                            Back to Home
                        </Button>
                    </Link>
                    
                    {/* Feature: Secondary "Report" button */}
                    <Button 
                        className="report-btn" 
                        size="large" 
                        icon="warning"
                        style={{ marginLeft: '10px' }}
                    >
                        Report Issue
                    </Button>
                </div>
            </div>
        </div>
    );
}

export default NotFound;