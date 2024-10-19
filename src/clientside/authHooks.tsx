"use client"

import { createContext, useContext, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';

interface User {
  id: string;
  email: string;
  name: string;
}

interface Session {
  user: User;
}

interface AuthContextType {
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  session: Session | null;
  isLoggingIn: boolean;
  isLoggingOut: boolean;
  sessionStatus: "loading" | "ready" | "fetching" | "down";
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children, namespace, signInPage, prefix }: any) => {
  const router = useRouter();
  const [session, setSession] = useState<Session | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);
  const [isLoggingOut, setIsLoggingOut] = useState<boolean>(false);
  const [sessionStatus, setSessionStatus] = useState<"loading" | "ready" | "fetching" | "down">("loading");

  const fetchSession = async (): Promise<void> => {
    try {
      const response = await fetch(`/api/hauth/session?namespace=${namespace}`, {
        method: "GET",
        cache: "no-store",
      });
      if (response.ok) {
        const data = await response.json();
        if (!data.err) {
          setSession(data as Session);
          setSessionStatus('ready');
        } else {
          setSessionStatus('down');
        }
      } else {
        setSessionStatus('down');
      }
    } catch (error) {
      setSessionStatus('down');
    }
  };

  useEffect(() => {
    const fetchAndSetSession = async (): Promise<() => void> => {
      await fetchSession();
      const intervalId = setInterval(fetchSession, 15000);
      return () => clearInterval(intervalId);
    };

    const intervalCleanup = fetchAndSetSession();

    return () => {
      intervalCleanup.then(cleanup => cleanup()); // intervalCleanup içindeki temizlik işlevini çağırıyoruz
    };
  }, []);



  const login = async (email: string, password: string): Promise<void> => {
    try {
      var tid = toast.loading("Giriş Yapılıyor")
      setIsLoggingIn(true);
      const response = await fetch(`/api/hauth/auth/authenticate?namespace=${namespace}`, {
        method: "POST",
        cache: "no-store",
        body: JSON.stringify({ email, password })
      });
      if (response.ok) {
        const data = await response.json();
        if (data.status) {
          toast.success("Giriş başarılı", { id: tid })
          router.push(`/api/hauth/redirectTo?redirectTo=${prefix}`);
        } else {

          toast.error(data.err, { id: tid })
          return setIsLoggingIn(false);
        }
      } else {
        toast.error("Sunucu hatası.", { id: tid })
        return setIsLoggingIn(false);
      }
    } catch (error) {
      console.error("Login error:", error);
    }
  };

  const logout = async () => {
    try {
      const response = await fetch(`/api/hauth/auth/authenticate?namespace=${namespace}`, {
        method: "DELETE",
      });
      if (response.ok) {
        const data = await response.json();
        window.location.reload()
        //router.push(`/api/hauth/redirectTo?redirectTo=${signInPage}`);
      }
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  return (
    <AuthContext.Provider value={{ isLoggingOut, isLoggingIn, session, sessionStatus, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};