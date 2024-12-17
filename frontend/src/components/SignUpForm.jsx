import React, { useState } from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import { FaUser, FaEnvelope, FaLock, FaPhone, FaCalendarAlt } from 'react-icons/fa';
import axios from 'axios';

const SignUpForm = () => {
  const [gender, setGender] = useState('');
  const [isLoginMode, setIsLoginMode] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    first_name: '',
    last_name: '',
    date_of_birth: '',
    email: '',
    password: '',
    confirmPassword: '',
    contact_number: '',
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Handle input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevData) => ({ ...prevData, [name]: value }));
  };

  // Handle form submission for sign-up
  const handleSignUp = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      const response = await axios.post('http://localhost:5000/api/signup', {
        ...formData,
        gender,
      });
      setSuccess(response.data.message); // Display success message
      setError('');
      setTimeout(() => {
        setIsLoginMode(true); // Switch to Sign-In mode after success
        resetForm();
      }, 3000);
    } catch (error) {
      console.error(error);
      setError(error.response?.data?.error || 'Error signing up. Please try again.');
    }
  };

  // Handle form submission for sign-in
  const handleSignIn = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const response = await axios.post('http://localhost:5000/api/signin', {
        email: formData.email,
        password: formData.password,
      });
      setSuccess(response.data.message); // Display success message
      setError('');
      console.log('User Data:', response.data.user); // Use this to manage logged-in state
      // Redirect or update UI for logged-in state if necessary
    } catch (error) {
      console.error(error);
      setError(error.response?.data?.error || 'Error signing in. Please try again.');
    }
  };

  // Reset form data and messages
  const resetForm = () => {
    setFormData({
      username: '',
      first_name: '',
      last_name: '',
      date_of_birth: '',
      email: '',
      password: '',
      confirmPassword: '',
      contact_number: '',
    });
    setGender('');
    setError('');
    setSuccess('');
  };

  // Toggle between sign-up and sign-in modes
  const handleModeSwitch = () => {
    resetForm();
    setIsLoginMode(!isLoginMode);
  };

  return (
    <div className="container d-flex align-items-center justify-content-center min-vh-100">
      <div className="card shadow-lg border-0 w-100" style={{ maxWidth: '900px', borderRadius: '15px' }}>
        <div className="row g-0">
          {/* Left Section */}
          <div
            className={`col-md-4 d-flex flex-column align-items-center justify-content-center text-center text-white p-4 position-relative ${
              isLoginMode ? 'order-md-2' : ''
            }`}
            style={{
              backgroundImage: 'url("/images/reg.png")',
              backgroundSize: 'cover',
              backgroundPosition: 'center',
              borderRadius: '15px 0 0 15px',
              overflow: 'hidden',
              minHeight: '100%',
            }}
          >
            <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', backgroundColor: 'rgba(0, 0, 0, 0.7)', zIndex: 1 }}></div>
            <div style={{ zIndex: 2, position: 'relative' }}>
              <h2 className="fw-bold mt-4">{isLoginMode ? 'Welcome Back' : 'Welcome'}</h2>
              <p className="lead" style={{ fontSize: '1rem' }}>
                {isLoginMode ? 'Sign in to access your account' : 'Sign up with your Google account!'}
              </p>
              <div className="text-center mt-4">
                <p className="mb-0 mt-4" style={{ fontSize: '0.9rem' }}>
                  {isLoginMode ? 'New here?' : 'Already have an account?'}
                </p>
                <button onClick={handleModeSwitch} className="btn btn-outline-light mt-2" style={{ borderRadius: '25px' }}>
                  {isLoginMode ? 'Sign Up' : 'Sign In'}
                </button>
              </div>
            </div>
          </div>

          {/* Right Section */}
          <div className={`col-md-8 p-5 ${isLoginMode ? 'order-md-1' : ''}`} style={{ transition: 'all 0.5s ease' }}>
            <h2 className="text-center fw-bold mb-4">{isLoginMode ? 'Sign In' : 'Sign Up'}</h2>

            {/* Success Alert */}
            {success && (
              <div className="alert alert-success text-center" role="alert">
                {success}
              </div>
            )}

            {/* Error Alert */}
            {error && (
              <div className="alert alert-danger text-center" role="alert">
                {error}
              </div>
            )}

            <form onSubmit={isLoginMode ? handleSignIn : handleSignUp}>
              <div className="row g-3">
                {isLoginMode ? (
                  // Sign-In Form
                  <>
                    <div className="col-12">
                      <label htmlFor="email" className="form-label">Your Email</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaEnvelope />
                        </span>
                        <input
                          type="email"
                          className="form-control border border-dark"
                          id="email"
                          name="email"
                          placeholder="you@example.com"
                          required
                          value={formData.email}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12">
                      <label htmlFor="password" className="form-label">Password</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaLock />
                        </span>
                        <input
                          type="password"
                          className="form-control border border-dark"
                          id="password"
                          name="password"
                          placeholder="********"
                          required
                          value={formData.password}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                  </>
                ) : (
                  // Sign-Up Form
                  <>
                    <div className="col-12 col-md-6">
                      <label htmlFor="username" className="form-label">Username</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaUser />
                        </span>
                        <input
                          type="text"
                          className="form-control border border-dark"
                          id="username"
                          name="username"
                          placeholder="Username"
                          required
                          value={formData.username}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12 col-md-6">
                      <label htmlFor="firstName" className="form-label">First Name</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaUser />
                        </span>
                        <input
                          type="text"
                          className="form-control border border-dark"
                          id="firstName"
                          name="first_name"
                          placeholder="First Name"
                          required
                          value={formData.first_name}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12 col-md-6">
                      <label htmlFor="lastName" className="form-label">Last Name</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaUser />
                        </span>
                        <input
                          type="text"
                          className="form-control border border-dark"
                          id="lastName"
                          name="last_name"
                          placeholder="Last Name"
                          required
                          value={formData.last_name}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12 col-md-6">
                      <label htmlFor="dateOfBirth" className="form-label">Date of Birth</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaCalendarAlt />
                        </span>
                        <input
                          type="date"
                          className="form-control border border-dark"
                          id="dateOfBirth"
                          name="date_of_birth"
                          required
                          value={formData.date_of_birth}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12">
                      <label className="form-label">Gender</label>
                      <div className="d-flex gap-2 mt-2">
                        <button
                          type="button"
                          className={`btn ${gender === 'Male' ? 'btn-primary text-white' : 'btn-outline-dark'} w-20`}
                          onClick={() => setGender('Male')}
                        >
                          Male
                        </button>
                        <button
                          type="button"
                          className={`btn ${gender === 'Female' ? 'btn-primary text-white' : 'btn-outline-dark'} w-20`}
                          onClick={() => setGender('Female')}
                        >
                          Female
                        </button>
                      </div>
                    </div>
                    <div className="col-12">
                      <label htmlFor="email" className="form-label">Your Email</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaEnvelope />
                        </span>
                        <input
                          type="email"
                          className="form-control border border-dark"
                          id="email"
                          name="email"
                          placeholder="you@example.com"
                          required
                          value={formData.email}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12 col-md-6">
                      <label htmlFor="password" className="form-label">Password</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaLock />
                        </span>
                        <input
                          type="password"
                          className="form-control border border-dark"
                          id="password"
                          name="password"
                          placeholder="********"
                          required
                          value={formData.password}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12 col-md-6">
                      <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaLock />
                        </span>
                        <input
                          type="password"
                          className="form-control border border-dark"
                          id="confirmPassword"
                          name="confirmPassword"
                          placeholder="********"
                          required
                          value={formData.confirmPassword}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-12">
                      <label htmlFor="contactNumber" className="form-label">Contact Number</label>
                      <div className="input-group">
                        <span className="input-group-text bg-light border border-dark text-dark">
                          <FaPhone />
                        </span>
                        <input
                          type="tel"
                          className="form-control border border-dark"
                          id="contactNumber"
                          name="contact_number"
                          placeholder="Phone Number"
                          required
                          value={formData.contact_number}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                  </>
                )}
              </div>
              <div className="mt-4 text-center">
                <button type="submit" className="btn btn-primary btn-lg w-100" style={{ borderRadius: '25px' }}>
                  {isLoginMode ? 'Sign In' : 'Sign Up'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SignUpForm;
