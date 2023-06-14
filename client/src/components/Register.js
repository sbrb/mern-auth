import React, { useState } from 'react'
import { NavLink } from "react-router-dom"
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import "./style.css"

export default function Register() {

    const [inpval, setInpval] = useState({
        name: "",
        email: "",
        password: "",
    });

    const setVal = (e) => {
        const { name, value } = e.target;

        setInpval(() => {
            return {
                ...inpval,
                [name]: value
            }
        })
    };

    const addUserdata = async (e) => {
        e.preventDefault();

        const { name, email, password } = inpval;

        if (name === "") {
            toast.warning("name is required!", {
                position: "top-center"
            });
        } else if (email === "") {
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
            const data = await fetch("/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    name, email, password
                })
            });

            const res = await data.json();
            // console.log(res.status);

            if (res.status === 201) {
                toast.success("Registration Successfully done.!", {
                    position: "top-center"
                });
                setInpval({ ...inpval, name: "", email: "", password: "" });
            }
        }
    }

    return (
        <>
            <section>
                <div className="form_data">
                    <div className="form_heading">
                        <h1>Create Account</h1>
                    </div>

                    <form>
                        <div className="form_input">
                            <input type="text" onChange={setVal} value={inpval.name} name="name" id="name" placeholder='Enter Your Name' />
                        </div>
                        <div className="form_input">
                            <input type="email" onChange={setVal} value={inpval.email} name="email" id="email" placeholder='Enter Your Email Address' />
                        </div>
                        <div className="form_input">
                            <div className="two">
                                <input type="password" value={inpval.password} onChange={setVal} name="password" id="password" placeholder='Enter Your password' />
                            </div>
                        </div>

                        <button className='btn' onClick={addUserdata}>Sign Up</button>
                        <p>Already have an account? <NavLink to="/">Log In</NavLink></p>
                    </form>
                    <ToastContainer />
                </div>
            </section>
        </>
    )
};