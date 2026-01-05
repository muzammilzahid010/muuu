import { MessageCircle } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import type { AppSettings } from "@shared/schema";

export function WhatsAppButton() {
  const { data } = useQuery<{ settings?: AppSettings }>({
    queryKey: ["/api/app-settings"],
  });

  const whatsappUrl = data?.settings?.whatsappUrl || "https://api.whatsapp.com/send?phone=&text=Admin";

  return (
    <a
      href={whatsappUrl}
      target="_blank"
      rel="noopener noreferrer"
      className="fixed bottom-6 right-6 z-50 flex items-center justify-center w-14 h-14 bg-green-500 hover:bg-green-600 text-white rounded-full shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-110"
      data-testid="button-whatsapp"
      aria-label="Contact us on WhatsApp"
    >
      <MessageCircle className="w-7 h-7" />
    </a>
  );
}
