import React, { useState } from 'react';
import { createPoll } from '../util/APIUtils';
import { MAX_CHOICES, POLL_QUESTION_MAX_LENGTH, POLL_CHOICE_MAX_LENGTH } from '../constants';
import './NewPoll.css';
import { Form, Input, Button, Icon, Select, Col, Row, notification, Tooltip } from 'antd';

const Option = Select.Option;
const { TextArea } = Input;

const NewPoll = (props) => {
    // 1. State Management with Hooks
    const [question, setQuestion] = useState({
        text: '',
        validateStatus: 'success',
        errorMsg: null
    });
    
    const [choices, setChoices] = useState([
        { text: '', validateStatus: 'success', errorMsg: null },
        { text: '', validateStatus: 'success', errorMsg: null }
    ]);
    
    const [pollLength, setPollLength] = useState({ days: 1, hours: 0 });
    const [isSubmitting, setIsSubmitting] = useState(false); // Feature: Loading state

    // 2. Validation Logic
    const validateQuestion = (text) => {
        if (text.length === 0) {
            return { validateStatus: 'error', errorMsg: 'Please enter your question!' };
        } else if (text.length > POLL_QUESTION_MAX_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Question is too long (Max ${POLL_QUESTION_MAX_LENGTH} chars)` };
        }
        return { validateStatus: 'success', errorMsg: null };
    };

    const validateChoice = (text) => {
        if (text.length === 0) {
            return { validateStatus: 'error', errorMsg: 'Please enter a choice!' };
        } else if (text.length > POLL_CHOICE_MAX_LENGTH) {
            return { validateStatus: 'error', errorMsg: `Choice is too long (Max ${POLL_CHOICE_MAX_LENGTH} chars)` };
        }
        return { validateStatus: 'success', errorMsg: null };
    };

    // 3. Handlers
    const handleQuestionChange = (event) => {
        const text = event.target.value;
        setQuestion({
            text,
            ...validateQuestion(text)
        });
    };

    const handleChoiceChange = (event, index) => {
        const text = event.target.value;
        const newChoices = [...choices];
        newChoices[index] = {
            text,
            ...validateChoice(text)
        };
        setChoices(newChoices);
    };

    const addChoice = () => {
        setChoices([...choices, { text: '', validateStatus: 'success', errorMsg: null }]);
    };

    const removeChoice = (indexToRemove) => {
        const newChoices = choices.filter((_, index) => index !== indexToRemove);
        setChoices(newChoices);
    };

    const handlePollDaysChange = (value) => setPollLength({ ...pollLength, days: value });
    const handlePollHoursChange = (value) => setPollLength({ ...pollLength, hours: value });

    const isFormInvalid = () => {
        if (question.validateStatus !== 'success') return true;
        for (let i = 0; i < choices.length; i++) {
            if (choices[i].validateStatus !== 'success') return true;
        }
        return false;
    };

    const handleSubmit = (event) => {
        event.preventDefault();
        setIsSubmitting(true); // Start loading

        const pollData = {
            question: question.text,
            choices: choices.map(choice => ({ text: choice.text })),
            pollLength: pollLength
        };

        createPoll(pollData)
            .then(response => {
                props.history.push("/");
            })
            .catch(error => {
                setIsSubmitting(false); // Stop loading on error
                if (error.status === 401) {
                    props.handleLogout('/login', 'error', 'You have been logged out.');
                } else {
                    notification.error({
                        message: 'Polling App',
                        description: error.message || 'Sorry! Something went wrong.'
                    });
                }
            });
    };

    return (
        <div className="new-poll-container">
            <div className="new-poll-content">
                <h1 className="page-title">Create a New Poll</h1>
                <Form onSubmit={handleSubmit} className="create-poll-form">
                    
                    {/* Question Section */}
                    <div className="form-section">
                        <Form.Item 
                            validateStatus={question.validateStatus}
                            help={question.errorMsg} 
                            className="poll-form-row"
                            label={<span className="form-label">Poll Question</span>}
                        >
                            <TextArea
                                placeholder="What would you like to ask?"
                                style={{ fontSize: '16px', borderRadius: '6px' }}
                                autosize={{ minRows: 3, maxRows: 6 }}
                                value={question.text}
                                onChange={handleQuestionChange} 
                            />
                            {/* Feature: Character Count */}
                            <div className="char-count">
                                {question.text.length} / {POLL_QUESTION_MAX_LENGTH}
                            </div>
                        </Form.Item>
                    </div>

                    {/* Choices Section */}
                    <div className="form-section">
                        <span className="form-label" style={{display: 'block', marginBottom: '10px'}}>Choices</span>
                        {choices.map((choice, index) => (
                            <PollChoice 
                                key={index} 
                                choice={choice} 
                                choiceNumber={index} 
                                removeChoice={removeChoice} 
                                handleChoiceChange={handleChoiceChange} 
                            />
                        ))}
                        
                        <Form.Item className="poll-form-row">
                            <Button 
                                type="dashed" 
                                onClick={addChoice} 
                                disabled={choices.length === MAX_CHOICES}
                                style={{ width: '100%', borderRadius: '6px' }}
                                icon="plus"
                            >
                                Add another choice
                            </Button>
                        </Form.Item>
                    </div>

                    {/* Poll Length Section */}
                    <div className="form-section">
                         <Row type="flex" align="middle" gutter={16}>
                             <Col>
                                <span className="form-label">Poll Duration:</span>
                                <Tooltip title="The poll will automatically close after this time.">
                                     <Icon type="question-circle-o" style={{ marginLeft: 5, color: '#999' }} />
                                </Tooltip>
                             </Col>
                             <Col>
                                <Select 
                                    name="days" 
                                    value={pollLength.days} 
                                    onChange={handlePollDaysChange} 
                                    style={{ width: 80 }}
                                >
                                    {Array.from(Array(8).keys()).map(i => <Option key={i} value={i}>{i} Days</Option>)}
                                </Select>
                             </Col>
                             <Col>
                                <Select 
                                    name="hours" 
                                    value={pollLength.hours} 
                                    onChange={handlePollHoursChange} 
                                    style={{ width: 80 }}
                                >
                                    {Array.from(Array(24).keys()).map(i => <Option key={i} value={i}>{i} Hours</Option>)}
                                </Select>
                             </Col>
                         </Row>
                    </div>

                    <Form.Item className="poll-form-row" style={{ marginTop: '30px' }}>
                        <Button 
                            type="primary" 
                            htmlType="submit" 
                            size="large" 
                            disabled={isFormInvalid() || isSubmitting}
                            loading={isSubmitting}
                            className="create-poll-form-button"
                            block
                        >
                            Create Poll
                        </Button>
                    </Form.Item>
                </Form>
            </div>
        </div>
    );
};

// Helper Component for Choices
const PollChoice = ({ choice, choiceNumber, removeChoice, handleChoiceChange }) => (
    <Form.Item 
        validateStatus={choice.validateStatus}
        help={choice.errorMsg} 
        className="poll-form-row"
    >
        <div style={{ display: 'flex', alignItems: 'center' }}>
            <Input 
                placeholder={'Choice ' + (choiceNumber + 1)}
                size="large"
                value={choice.text}
                onChange={(event) => handleChoiceChange(event, choiceNumber)}
                style={{ borderRadius: '6px' }}
            />
            {choiceNumber > 1 && (
                <Icon
                    className="dynamic-delete-button"
                    type="close-circle" // Feature: Better remove icon
                    theme="filled"
                    style={{ fontSize: '20px', marginLeft: '10px', color: '#ff4d4f', cursor: 'pointer' }}
                    onClick={() => removeChoice(choiceNumber)}
                />
            )}
        </div>
    </Form.Item>
);

export default NewPoll;