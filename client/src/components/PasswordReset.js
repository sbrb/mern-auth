import React, { useState } from 'react'
import { NavLink } from 'react-router-dom';
import { ToastContainer, toast } from 'react-toastify';

export default function PasswordReset() {

    const [email, setEmail] = useState("");
    const [message, setMessage] = useState("");

    const setVal = (e) => {
        setEmail(e.target.value)
    }

    const sendLink = async (e) => {
        e.preventDefault();

        if (email === "") {
            toast.error("email is required!", {
                position: "top-center"
            });
        } else if (!email.includes("@")) {
            toast.warning("includes @ in your email!", {
                position: "top-center"
            });
        } else {
            const res = await fetch("/sendpasswordlink", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ email })
            });

            const data = await res.json();

            if (data.status === 201) {
                setEmail("");
                setMessage(true)
            } else {
                toast.error("Invalid User", {
                    position: "top-center"
                })
            }
        }
    }

    return (
        <>
            <section>
                <div className="form_data">
                    <div className="form_heading">
                        <h2>Forgot your password?</h2>
                    </div>

                    {message ? <p style={{ color: "green", fontWeight: "bold" }}>Password reset link has been send Successfully in Your Email</p> : ""}
                    <form>
                        <div className="form_input">
                            <input type="email" value={email} onChange={setVal} name="email" id="email" placeholder='Email' />
                        </div>

                        <button className='btn' onClick={sendLink}>Send password reset info</button>
                    </form>
                    <ToastContainer />
                    <p>Already have an account? <NavLink to="/">Log In</NavLink></p>
                </div>
            </section>
        </>
    )
};