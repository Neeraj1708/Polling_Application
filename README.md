# 🗳️ Full Stack Polling Application

A full-stack, real-time polling application where users can create polls, vote on active polls, and view dynamic results. Built with a robust **Spring Boot 3** backend and a responsive **React.js** frontend, deployed on the cloud for global access.

### 🚀 **Live Demo**
> **Frontend:** [https://polling-application-one.vercel.app](https://polling-application-one.vercel.app)  
> **Backend API:** [https://polling-application-vhq5.onrender.com](https://polling-application-vhq5.onrender.com)

---

## 🛠️ Tech Stack

### **Backend**
* **Java 17** (LTS)
* **Spring Boot 3.4** (REST APIs)
* **Spring Security 6** (Authentication & Authorization)
* **JWT** (Stateless JSON Web Token Security)
* **Spring Data JPA / Hibernate** (ORM)
* **MySQL** (Aiven Cloud Database)
* **Maven** (Build Tool)

### **Frontend**
* **React.js** (Functional Components & Hooks)
* **Ant Design** (UI Library)
* **Axios** (HTTP Client)
* **React Router** (Navigation)

### **DevOps & Deployment**
* **Render** (Backend Hosting)
* **Vercel** (Frontend Hosting)
* **Aiven** (Managed MySQL Cloud Database)
* **Docker** (Containerization support)

---

## ✨ Features

* **Authentication:** Secure Sign Up & Login with JWT (Access Tokens).
* **Role-Based Access Control (RBAC):**
    * **User:** Create polls, vote in polls, view results.
    * **Admin:** Manage users and polls (Scalable architecture).
* **Poll Management:** Create polls with configurable expiration times (Days/Hours).
* **Voting System:** Real-time vote calculation and duplicate vote prevention.
* **Dynamic Dashboard:** View polls, vote counts, and winner statistics instantly.
* **Cloud Architecture:** Fully decoupled frontend and backend communicating via REST APIs.

 

## ⚙️ Local Setup Guide

Follow these steps to run the project locally on your machine.

### **1. Prerequisites**
* **Java 17+** Installed
* **Node.js & npm** Installed
* **MySQL** Installed (or use a cloud connection)

### **2. Database Setup**
Create a MySQL database named `polling_app`.
```sql
CREATE DATABASE polling_app;
