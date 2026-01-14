import React from 'react';
import './Poll.css';
import { Avatar, Icon, Radio, Button, Progress, Tag, Tooltip, message } from 'antd';
import { Link } from 'react-router-dom';
import { getAvatarColor } from '../util/Colors';
import { formatDateTime } from '../util/Helpers';

const RadioGroup = Radio.Group;

const Poll = (props) => {
    
    // 1. Helper Functions
    const calculatePercentage = (choice) => {
        if (props.poll.totalVotes === 0) return 0;
        return (choice.voteCount * 100) / props.poll.totalVotes;
    };

    const isSelected = (choice) => {
        return props.poll.selectedChoice === choice.id;
    };

    const getWinningChoice = () => {
        return props.poll.choices.reduce((prevChoice, currentChoice) =>
            currentChoice.voteCount > prevChoice.voteCount ? currentChoice : prevChoice,
            { voteCount: -Infinity }
        );
    };

    const getTimeRemaining = (poll) => {
        const expirationTime = new Date(poll.expirationDateTime).getTime();
        const currentTime = new Date().getTime();
        var difference_ms = expirationTime - currentTime;

        if(difference_ms < 0) return "Expired";

        var seconds = Math.floor((difference_ms / 1000) % 60);
        var minutes = Math.floor((difference_ms / 1000 / 60) % 60);
        var hours = Math.floor((difference_ms / (1000 * 60 * 60)) % 24);
        var days = Math.floor(difference_ms / (1000 * 60 * 60 * 24));

        if (days > 0) return days + " days left";
        if (hours > 0) return hours + " hours left";
        if (minutes > 0) return minutes + " minutes left";
        return seconds + " seconds left";
    };

    // 2. Feature: Share Poll Logic
    const handleShare = () => {
        // Copies current URL (or you can construct a specific one)
        const dummyUrl = `https://myapp.com/poll/${props.poll.id}`;
        navigator.clipboard.writeText(dummyUrl).then(() => {
            message.success("Link copied to clipboard!");
        });
    };

    // 3. Render Choices
    const pollChoices = [];
    if (props.poll.selectedChoice || props.poll.expired) {
        const winningChoice = props.poll.expired ? getWinningChoice() : null;

        props.poll.choices.forEach(choice => {
            pollChoices.push(
                <CompletedOrVotedPollChoice
                    key={choice.id}
                    choice={choice}
                    isWinner={winningChoice && choice.id === winningChoice.id}
                    isSelected={isSelected(choice)}
                    percentVote={calculatePercentage(choice)}
                />
            );
        });
    } else {
        props.poll.choices.forEach(choice => {
            pollChoices.push(
                <Radio className="poll-choice-radio" key={choice.id} value={choice.id}>
                    {choice.text}
                </Radio>
            );
        });
    }

    const expirationStatus = props.poll.expired ? "Closed" : "Active";
    const statusColor = props.poll.expired ? "red" : "green";

    return (
        <div className="poll-content">
            <div className="poll-header">
                <div className="poll-header-top">
                    <div className="poll-creator-info">
                        <Link className="creator-link" to={`/users/${props.poll.createdBy.username}`}>
                            <Avatar className="poll-creator-avatar"
                                style={{ backgroundColor: getAvatarColor(props.poll.createdBy.name) }} >
                                {props.poll.createdBy.name[0].toUpperCase()}
                            </Avatar>
                            <div className="creator-details">
                                <span className="poll-creator-name">
                                    {props.poll.createdBy.name}
                                </span>
                                <span className="poll-creation-date">
                                    {formatDateTime(props.poll.creationDateTime)}
                                </span>
                            </div>
                        </Link>
                    </div>
                    {/* Feature: Status & Share */}
                    <div className="poll-actions">
                        <Tag color={statusColor} style={{marginRight: 10}}>{expirationStatus}</Tag>
                        <Tooltip title="Share this poll">
                            <Icon type="share-alt" className="share-icon" onClick={handleShare} />
                        </Tooltip>
                    </div>
                </div>

                <div className="poll-question">
                    {props.poll.question}
                </div>
            </div>

            <div className="poll-choices">
                <RadioGroup
                    className="poll-choice-radio-group"
                    onChange={props.handleVoteChange}
                    value={props.currentVote}>
                    {pollChoices}
                </RadioGroup>
            </div>

            <div className="poll-footer">
                {
                    !(props.poll.selectedChoice || props.poll.expired) ?
                        (<Button className="vote-button" type="primary" disabled={!props.currentVote} onClick={props.handleVoteSubmit}>Vote</Button>) : null
                }
                <div className="poll-footer-meta">
                    <span className="total-votes"><Icon type="bar-chart" /> {props.poll.totalVotes} votes</span>
                    <span className="separator">•</span>
                    <span className="time-left">
                        <Icon type="clock-circle-o" /> {
                            props.poll.expired ? "Final results" :
                                getTimeRemaining(props.poll)
                        }
                    </span>
                </div>
            </div>
        </div>
    );
}

// 4. Enhanced Result Component with AntD Progress
const CompletedOrVotedPollChoice = ({ choice, isWinner, isSelected, percentVote }) => {
    return (
        <div className={`cv-poll-choice ${isWinner ? 'winner' : ''}`}>
            <div className="cv-choice-header">
                 <span className="cv-choice-text">{choice.text}</span>
                 {isSelected && <Icon type="check-circle" theme="twoTone" twoToneColor="#52c41a" style={{marginLeft: 8}}/>}
            </div>
            
            <div className="cv-progress-wrapper">
                 {/* Feature: Smooth Progress Bar */}
                 <Progress 
                    percent={Math.round(percentVote * 100) / 100} 
                    status={isWinner ? "success" : "normal"}
                    strokeColor={isWinner ? "#52c41a" : "#1890ff"} 
                    strokeWidth={12}
                    showInfo={true} // Shows the % automatically
                 />
                 <div className="cv-choice-count">{choice.voteCount} votes</div>
            </div>
        </div>
    );
}

export default Poll;