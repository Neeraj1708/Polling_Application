import React from 'react';
import { Spin, Icon } from 'antd';
import './LoadingIndicator.css'; // Import the new CSS animations

export default function LoadingIndicator(props) {
    // 1. Custom colorful spinner icon
    const antIcon = (
        <Icon 
            type="loading-3-quarters" 
            style={{ fontSize: 40, color: '#722ed1' }} 
            spin 
        />
    );

    return (
        <div className="loading-container">
            <Spin indicator={antIcon} />
            {/* 2. Animated Text with Fallback */}
            <h3 className="loading-text">
                {props.text || "Loading..."}
            </h3>
        </div>
    );
}