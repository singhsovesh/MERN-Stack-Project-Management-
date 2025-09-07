
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import { Toaster } from "sonner";
import { AuthProvider } from "./auth-context"; // ✅ Fixed: AuthProvider instead of AuthPovider

export const queryClient = new QueryClient();

const ReactQueryProvider = ({ children }: { children: React.ReactNode }) => {
    return (
        <QueryClientProvider client={queryClient}>
            <AuthProvider> {/* ✅ Fixed: AuthProvider instead of AuthPovider */}
            {children}
            <Toaster position="top-center" richColors/>
            </AuthProvider> {/* ✅ Fixed: AuthProvider instead of AuthPovider */}
        </QueryClientProvider>
    );
};

export default ReactQueryProvider;