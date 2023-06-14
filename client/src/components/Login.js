import React, { useState } from 'react'
import { NavLink, useNavigate } from "react-router-dom"
import { ToastContainer, toast } from 'react-toastify';
import "./style.css";

export default function Login() {

    const [inpval, setInpval] = useState({
        email: "",
        password: "",
    });

    const history = useNavigate();

    const setVal = (e) => {
        const { name, value } = e.target;

        setInpval(() => {
            return {
                ...inpval,
                [name]: value
            }
        })
    };


    const loginuser = async (e) => {
        e.preventDefault();

        const { email, password } = inpval;

        if (email === "") {
            toast.error("email is required!", {
                position: "top-center"
            });
        } else if (!email.includes("@")) {
            toast.warning("includes @ in your email!", {
                position: "top-center"
            });
        } else if (password === "") {
            toast.error("password is required!", {
                position: "top-center"
            });
        } else if (password.length < 6) {
            toast.error("password must be 6 char!", {
                position: "top-center"
            });
        } else {

            const data = await fetch("/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    email, password
                })
            });

            const res = await data.json();

            if (res.status === 201) {
                localStorage.setItem("usersdatatoken", res.result.token);
                history("/dash")
                setInpval({ ...inpval, email: "", password: "" });
            } else {
                toast.error("Invalid Credentials", {
                    position: "top-center"
                });
            }
        }
    }

    return (
        <>
            <section>
                <div className="form_data">
                    <div className="form_heading">
                        <h1>Log In</h1>
                    </div>

                    <form>
                        <div className="form_input">
                            <input type="email" value={inpval.email} onChange={setVal} name="email" id="email" placeholder='Email' />
                        </div>
                        <div className="form_input">
                            <div className="two">
                                <input type="password" onChange={setVal} value={inpval.password} name="password" id="password" placeholder='Password' />
                            </div>
                        </div>

                        <button className='btn' onClick={loginuser}>Login</button>
                        <p>Not registered? <NavLink to="/register"> Create an Account</NavLink> </p>
                        <p style={{ color: "black", fontWeight: "bold" }}> <NavLink to="/password-reset">Forgot password?</NavLink> </p>
                    </form>
                    <ToastContainer />
                </div>
            </section>
        </>
    )
};