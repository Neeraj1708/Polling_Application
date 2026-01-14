import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import { Route, withRouter, Switch } from 'react-router-dom';
import { getCurrentUser } from '../util/APIUtils';
import { ACCESS_TOKEN } from '../constants';

// ... (keep your other imports like PollList, Login, etc.) ...
import PollList from '../poll/PollList';
import NewPoll from '../poll/NewPoll';
import Login from '../user/login/Login';
import Signup from '../user/signup/Signup';
import Profile from '../user/profile/Profile';
import AppHeader from '../common/AppHeader';
import NotFound from '../common/NotFound';
import LoadingIndicator from '../common/LoadingIndicator';
import PrivateRoute from '../common/PrivateRoute';
import { Layout, notification, BackTop } from 'antd';

const { Content, Footer } = Layout;

const App = (props) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    notification.config({
      placement: 'topRight',
      top: 70,
      duration: 3,
    });
  }, []);

  const loadCurrentUser = useCallback(() => {
    setIsLoading(true);
    getCurrentUser()
      .then(response => {
        setCurrentUser(response);
        setIsAuthenticated(true);
        setIsLoading(false);
      })
      .catch(error => {
        setIsLoading(false);
      });
  }, []);

  useEffect(() => {
    loadCurrentUser();
  }, [loadCurrentUser]);

  // --- UPDATED LOGOUT FUNCTION ---
  const handleLogout = (redirectTo = "/login", notificationType = "success", description = "You're successfully logged out.") => {
    localStorage.removeItem(ACCESS_TOKEN);

    setCurrentUser(null);
    setIsAuthenticated(false);

    // Redirects to /login by default now
    props.history.push(redirectTo);

    notification[notificationType]({
      message: 'Polling App',
      description: description,
    });
  };
  // -------------------------------

  const handleLogin = () => {
    notification.success({
      message: 'Polling App',
      description: "You're successfully logged in.",
    });
    loadCurrentUser();
    props.history.push("/");
  };

  if (isLoading) {
    return <LoadingIndicator />;
  }

  return (
      <Layout className="app-container" style={{ minHeight: '100vh' }}>
        <AppHeader 
          isAuthenticated={isAuthenticated} 
          currentUser={currentUser} 
          onLogout={handleLogout} 
        />

        <Content className="app-content" style={{ padding: '0 50px', marginTop: 64 }}>
          <div className="container" style={{ background: '#fff', padding: 24, minHeight: 380, marginTop: '20px', borderRadius: '8px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>
            <Switch>      
              <Route exact path="/" 
                render={(routeProps) => <PollList isAuthenticated={isAuthenticated} 
                    currentUser={currentUser} handleLogout={handleLogout} {...routeProps} />}>
              </Route>
              <Route path="/login" 
                render={(routeProps) => <Login onLogin={handleLogin} {...routeProps} />}></Route>
              <Route path="/signup" component={Signup}></Route>
              <Route path="/users/:username" 
                render={(routeProps) => <Profile isAuthenticated={isAuthenticated} currentUser={currentUser} {...routeProps}  />}>
              </Route>
              <PrivateRoute 
                authenticated={isAuthenticated} 
                path="/poll/new" 
                component={NewPoll} 
                handleLogout={handleLogout}
              />
              <Route component={NotFound}></Route>
            </Switch>
          </div>
        </Content>

        <Footer style={{ textAlign: 'center', background: '#f0f2f5' }}>
          Polling App ©{new Date().getFullYear()}
        </Footer>
        <BackTop />
      </Layout>
  );
}

export default withRouter(App);