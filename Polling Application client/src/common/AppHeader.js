import React from 'react';
import { Link, withRouter } from 'react-router-dom';
import './AppHeader.css';
import pollIcon from '../poll.svg';
import { Layout, Menu, Dropdown, Icon, Avatar, Button } from 'antd';

const { Header } = Layout;

const AppHeader = (props) => {
    const handleMenuClick = ({ key }) => {
        if (key === "logout") {
            props.onLogout();
        }
    };

    let menuItems;
    if (props.currentUser) {
        menuItems = [
            <Menu.Item key="/">
                <Link to="/">
                    <Icon type="home" className="nav-icon" /> Home
                </Link>
            </Menu.Item>,
            <Menu.Item key="/poll/new">
                <Link to="/poll/new">
                    <img src={pollIcon} alt="poll" className="poll-icon" /> Create Poll
                </Link>
            </Menu.Item>,
            <Menu.Item key="/profile" className="profile-menu">
                <ProfileDropdownMenu
                    currentUser={props.currentUser}
                    handleMenuClick={handleMenuClick}
                />
            </Menu.Item>
        ];
    } else {
        menuItems = [
            <Menu.Item key="/login">
                <Link to="/login">
                    <Button type="primary" ghost>Login</Button>
                </Link>
            </Menu.Item>,
            <Menu.Item key="/signup">
                <Link to="/signup">
                    <Button type="primary">Signup</Button>
                </Link>
            </Menu.Item>
        ];
    }

    return (
        <Header className="app-header">
            <div className="container">
                <div className="app-title">
                    <Link to="/">
                        <Icon type="api" style={{ marginRight: '8px', color: '#722ed1' }} />
                        Polling App
                    </Link>
                </div>
                <Menu
                    className="app-menu"
                    mode="horizontal"
                    selectedKeys={[props.location.pathname]}
                    style={{ lineHeight: '64px' }}
                >
                    {menuItems}
                </Menu>
            </div>
        </Header>
    );
}

const ProfileDropdownMenu = (props) => {
    const dropdownMenu = (
        <Menu onClick={props.handleMenuClick} className="profile-dropdown-menu">
            <Menu.Item key="user-info" className="dropdown-item" disabled>
                <div className="user-full-name-info">
                    {props.currentUser.name}
                </div>
                <div className="username-info">
                    @{props.currentUser.username}
                </div>
            </Menu.Item>
            <Menu.Divider />
            <Menu.Item key="profile" className="dropdown-item">
                <Link to={`/users/${props.currentUser.username}`}>
                    <Icon type="user" className="dropdown-icon" /> Profile
                </Link>
            </Menu.Item>
            <Menu.Item key="logout" className="dropdown-item">
                <Icon type="logout" className="dropdown-icon" /> Logout
            </Menu.Item>
        </Menu>
    );

    // Get the first letter of the name for the Avatar
    const initial = props.currentUser.name ? props.currentUser.name.charAt(0).toUpperCase() : 'U';

    return (
        <Dropdown
            overlay={dropdownMenu}
            trigger={['click']}
            getPopupContainer={() => document.getElementsByClassName('profile-menu')[0]}>
            <a className="ant-dropdown-link" href="#!" onClick={e => e.preventDefault()}>
                {/* Feature: Colorful Avatar with User's Initial */}
                <Avatar style={{ backgroundColor: '#87d068', marginRight: 8 }}>
                    {initial}
                </Avatar>
                <Icon type="down" />
            </a>
        </Dropdown>
    );
}

export default withRouter(AppHeader);