import { useToast } from "@/hooks/use-toast"
import { AlertCircle, CheckCircle2 } from "lucide-react"
import {
  Toast,
  ToastClose,
  ToastDescription,
  ToastProvider,
  ToastTitle,
  ToastViewport,
} from "@/components/ui/toast"

export function Toaster() {
  const { toasts } = useToast()

  return (
    <ToastProvider>
      {toasts.map(function ({ id, title, description, action, variant, ...props }) {
        const isDestructive = variant === "destructive"
        return (
          <Toast key={id} variant={variant} {...props}>
            <div className="flex-shrink-0">
              {isDestructive ? (
                <AlertCircle className="h-6 w-6 text-white" />
              ) : (
                <CheckCircle2 className="h-6 w-6 text-green-500" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              {title && <ToastTitle>{title}</ToastTitle>}
              {description && (
                <ToastDescription>{description}</ToastDescription>
              )}
            </div>
            {action}
            <ToastClose />
          </Toast>
        )
      })}
      <ToastViewport />
    </ToastProvider>
  )
}
