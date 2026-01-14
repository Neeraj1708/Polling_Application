import React from 'react';
import './ServerError.css';
import { Link } from 'react-router-dom';
import { Button, Icon } from 'antd';

const ServerError = () => {
    
    // Feature: Reload the page to see if the server recovers
    const handleRetry = () => {
        window.location.reload();
    };

    return (
        <div className="server-error-page">
            <div className="server-error-content">
                {/* 1. Thematic Illustration */}
                <div className="server-icon-container">
                    <Icon type="cloud-sync" className="server-error-icon" />
                    <div className="server-shadow"></div>
                </div>

                {/* 2. Pulsing Title */}
                <h1 className="server-error-title">
                    500
                </h1>
                
                <div className="server-error-desc">
                    Oops! Something went wrong at our Server.
                    <br />
                    It's not you, it's us. Please try again later.
                </div>
                
                {/* 3. Action Buttons */}
                <div className="server-error-buttons">
                    {/* Feature: Retry Button */}
                    <Button 
                        type="primary" 
                        size="large" 
                        icon="reload" 
                        onClick={handleRetry}
                        className="retry-btn"
                    >
                        Retry Connection
                    </Button>

                    <Link to="/">
                        <Button 
                            className="server-back-btn" 
                            size="large" 
                            ghost
                            type="primary"
                        >
                            Back to Home
                        </Button>
                    </Link>
                </div>
            </div>
        </div>
    );
}

export default ServerError;