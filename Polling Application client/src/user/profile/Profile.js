import React, { useState, useEffect } from 'react';
import PollList from '../../poll/PollList';
import { getUserProfile } from '../../util/APIUtils';
import { Avatar, Tabs, Icon, Row, Col, Card } from 'antd';
import { getAvatarColor } from '../../util/Colors';
import { formatDate } from '../../util/Helpers';
import LoadingIndicator from '../../common/LoadingIndicator';
import './Profile.css';
import NotFound from '../../common/NotFound';
import ServerError from '../../common/ServerError';

const TabPane = Tabs.TabPane;

const Profile = (props) => {
    const [user, setUser] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [notFound, setNotFound] = useState(false);
    const [serverError, setServerError] = useState(false);

    const loadUserProfile = (username) => {
        setIsLoading(true);

        getUserProfile(username)
            .then(response => {
                setUser(response);
                setIsLoading(false);
            })
            .catch(error => {
                if (error.status === 404) {
                    setNotFound(true);
                } else {
                    setServerError(true);
                }
                setIsLoading(false);
            });
    };

    useEffect(() => {
        const username = props.match.params.username;
        loadUserProfile(username);
    }, [props.match.params.username]);

    if (isLoading) return <LoadingIndicator />;
    if (notFound) return <NotFound />;
    if (serverError) return <ServerError />;

    return (
        <div className="profile">
            {user ? (
                <div className="user-profile-card">
                    
                    {/* New Header Structure with Overlap */}
                    <div className="user-profile-header-wrapper">
                        {/* Colored Cover Background */}
                        <div className="user-cover-bg"></div>
                        
                        {/* Content container that overlaps the cover */}
                        <div className="user-info-overlap-container">
                            <div className="user-avatar-box">
                                <Avatar 
                                    className="user-avatar-circle" 
                                    style={{ backgroundColor: getAvatarColor(user.name) }}
                                >
                                    {user.name[0].toUpperCase()}
                                </Avatar>
                            </div>
                            <div className="user-names-container">
                                <h2 className="full-name">{user.name}</h2>
                                <p className="username">@{user.username}</p>
                                <div className="user-joined-date">
                                    <Icon type="calendar" style={{marginRight: '5px'}}/> 
                                    Joined {formatDate(user.joinedAt)}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Stats Row */}
                    <div className="user-stats-row">
                        <Row gutter={24} type="flex" justify="center">
                            <Col xs={24} sm={10} md={8}>
                                <Card className="stat-card" bordered={false} hoverable>
                                    <div className="stat-content">
                                        <div className="stat-icon-bg primary-blue">
                                            <Icon type="bar-chart" />
                                        </div>
                                        <div className="stat-text">
                                            <div className="stat-value">{user.pollCount}</div>
                                            <div className="stat-title">Polls Created</div>
                                        </div>
                                    </div>
                                </Card>
                            </Col>
                            <Col xs={24} sm={10} md={8}>
                                <Card className="stat-card" bordered={false} hoverable>
                                    <div className="stat-content">
                                        <div className="stat-icon-bg success-teal">
                                            <Icon type="check-circle" />
                                        </div>
                                        <div className="stat-text">
                                            <div className="stat-value">{user.voteCount}</div>
                                            <div className="stat-title">Votes Cast</div>
                                        </div>
                                    </div>
                                </Card>
                            </Col>
                        </Row>
                    </div>

                    {/* Tabs Section */}
                    <div className="user-poll-details">
                        <Tabs defaultActiveKey="1" animated={false} size="large" className="profile-tabs">
                            <TabPane 
                                tab={<span><Icon type="solution" /> Created Polls</span>} 
                                key="1"
                            >
                                <PollList username={props.match.params.username} type="USER_CREATED_POLLS" />
                            </TabPane>
                            <TabPane 
                                tab={<span><Icon type="check-square" /> Voted Polls</span>} 
                                key="2"
                            >
                                <PollList username={props.match.params.username} type="USER_VOTED_POLLS" />
                            </TabPane>
                        </Tabs>
                    </div>
                </div>
            ) : null}
        </div>
    );
}

export default Profile;