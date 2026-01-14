import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './app/App';
// 1. Change this import to get 'unregister'
import { unregister } from './registerServiceWorker';
import { BrowserRouter as Router } from 'react-router-dom';

ReactDOM.render(
    <Router>
        <App />
    </Router>, 
    document.getElementById('root')
);

// 2. Change this function call to unregister()
unregister();