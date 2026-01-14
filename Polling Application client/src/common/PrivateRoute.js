import React, { useEffect } from 'react';
import { Route, Redirect } from "react-router-dom";
import { notification } from 'antd';

// Feature 1: A dedicated component to handle the Redirect + Notification logic
const RedirectToLogin = ({ location }) => {
    
    // Use useEffect to trigger the notification only once when this component mounts
    useEffect(() => {
        notification.warning({
            message: 'Polling App',
            description: 'You need to be logged in to access this page.',
            duration: 3,
        });
    }, []); // Empty dependency array means this runs once on mount

    return (
        <Redirect
            to={{
                pathname: '/login',
                state: { from: location }
            }}
        />
    );
};

const PrivateRoute = ({ component: Component, authenticated, ...rest }) => (
    <Route
        {...rest}
        render={props =>
            authenticated ? (
                // If authenticated, render the requested component
                <Component {...rest} {...props} />
            ) : (
                // Feature 2: If not, render our smart Redirect component
                <RedirectToLogin location={props.location} />
            )
        }
    />
);

export default PrivateRoute;