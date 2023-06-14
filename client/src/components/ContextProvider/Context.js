import React, { createContext, useState } from 'react'


export const LoginContext = createContext("");

export default function Context({ children }){
    const [logindata,setLoginData] = useState("");

  return (
    <>
    <LoginContext.Provider value={{logindata,setLoginData}}>
        {children}
    </LoginContext.Provider>
    </>
  )
};