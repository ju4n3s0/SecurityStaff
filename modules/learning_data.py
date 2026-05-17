LESSONS = [
    {
        "id": 1,
        "title": "¿Qué es el phishing?",
        "icon": "🎣",
        "content": (
            "El phishing es una técnica de engaño usada por delincuentes para robar "
            "información confidencial como contraseñas, números de tarjeta o datos "
            "personales. El atacante se hace pasar por una entidad de confianza "
            "(un banco, el gobierno, una empresa conocida) y te pide que actúes rápido. "
            "Recuerda: ninguna entidad legítima te pedirá tu contraseña por correo o mensaje."
        ),
        "tip": "Si tienes dudas, cuelga y llama directamente al número oficial de la entidad.",
    },
    {
        "id": 2,
        "title": "Cómo identificar enlaces sospechosos",
        "icon": "🔗",
        "content": (
            "Antes de hacer clic en un enlace, observa cuidadosamente la dirección web. "
            "Los estafadores usan dominios muy parecidos al original: por ejemplo "
            "'bancolombia-seguro.xyz' en lugar de 'bancolombia.com'. "
            "También usan acortadores de URL (bit.ly, tinyurl) para esconder el destino real. "
            "Si el enlace no coincide exactamente con el sitio oficial, no hagas clic."
        ),
        "tip": "Pasa el cursor sobre el enlace sin hacer clic para ver a dónde lleva realmente.",
    },
    {
        "id": 3,
        "title": "Las señales de urgencia falsa",
        "icon": "⚡",
        "content": (
            "Una táctica favorita de los estafadores es crear pánico: 'Su cuenta será bloqueada', "
            "'Tiene 2 horas para responder', 'Pago urgente pendiente'. "
            "Esta presión artificial busca que actúes sin pensar. "
            "Las instituciones reales siempre dan tiempo suficiente para resolver cualquier situación "
            "y nunca te amenazan por correo o mensaje de texto."
        ),
        "tip": "Cuando sientas presión o urgencia en un mensaje, detente. Tómate tu tiempo antes de actuar.",
    },
    {
        "id": 4,
        "title": "Correos falsos del banco",
        "icon": "🏦",
        "content": (
            "Los bancos nunca te pedirán que confirmes tu clave, número de tarjeta o datos "
            "personales por correo electrónico o SMS. "
            "Un correo falso del banco puede tener el logo correcto y lucir muy oficial, "
            "pero si te pide hacer clic en un enlace para 'verificar' o 'actualizar' tu cuenta, "
            "es una señal de alerta. Entra siempre al sitio web del banco escribiendo "
            "la dirección directamente en tu navegador."
        ),
        "tip": "Guarda el número oficial de tu banco en tu teléfono y llámalo si tienes dudas.",
    },
    {
        "id": 5,
        "title": "Premios y sorteos falsos",
        "icon": "🎰",
        "content": (
            "¿Te llegó un mensaje diciendo que ganaste un premio, un viaje o dinero? "
            "Este es uno de los engaños más comunes. "
            "Los estafadores piden que pagues un 'impuesto' o 'gastos de envío' para recibir el premio, "
            "o que des tus datos bancarios. Nadie gana premios de sorteos en los que no participó. "
            "Elimina estos mensajes sin responderlos."
        ),
        "tip": "Si no participaste en ningún concurso, no pudiste ganar nada.",
    },
    {
        "id": 6,
        "title": "Llamadas y mensajes del 'gobierno'",
        "icon": "🏛️",
        "content": (
            "Estafadores se hacen pasar por funcionarios de la DIAN, el Ministerio de Salud, "
            "o la Policía, diciendo que tienes una deuda o que debes actualizar tus datos "
            "para seguir recibiendo subsidios. "
            "Las entidades gubernamentales nunca te pedirán información bancaria por teléfono "
            "ni te amenazarán con 'consecuencias legales inmediatas' si no actúas al instante."
        ),
        "tip": "Cuelga y busca el número oficial de la entidad en internet para verificar.",
    },
    {
        "id": 7,
        "title": "Cómo proteger tus contraseñas",
        "icon": "🔐",
        "content": (
            "Una contraseña segura tiene al menos 8 caracteres e incluye letras, números y símbolos. "
            "Nunca uses la misma contraseña para varios servicios. "
            "No compartas tus contraseñas por correo, chat ni teléfono, "
            "ni siquiera con personas que dicen ser de soporte técnico. "
            "Si crees que alguien tiene tu contraseña, cámbiala de inmediato."
        ),
        "tip": "Usa una frase fácil de recordar para ti pero difícil de adivinar, como: MiPerro2024!",
    },
]

QUESTIONS = [
    {
        "id": 1,
        "scenario": "📧 Correo recibido",
        "question": (
            "Recibes este correo: 'Estimado cliente, su cuenta Bancolombia ha sido BLOQUEADA "
            "por actividad sospechosa. Haga clic aquí para desbloquearla: "
            "http://bancolombia-soporte.xyz'. ¿Qué debes hacer?"
        ),
        "options": [
            "Hacer clic en el enlace inmediatamente para desbloquear la cuenta",
            "Llamar directamente al número oficial del banco en el reverso de tu tarjeta",
            "Responder el correo con tus datos para que te ayuden",
            "Reenviar el correo a tus contactos para que estén alertas",
        ],
        "correct_answer": 1,
        "explanation": (
            "La opción correcta es llamar al banco directamente usando el número oficial. "
            "El enlace 'bancolombia-soporte.xyz' es falso — el dominio real es 'bancolombia.com'. "
            "Nunca hagas clic en enlaces de correos de alerta bancaria."
        ),
    },
    {
        "id": 2,
        "scenario": "📱 Mensaje de texto",
        "question": (
            "Recibes un SMS: '¡FELICITACIONES! Ganó $5.000.000 en nuestro sorteo. "
            "Para reclamar su premio envíe sus datos bancarios a este número antes de las 6pm.' "
            "¿Cuál es la señal más clara de que es una estafa?"
        ),
        "options": [
            "El mensaje tiene signos de exclamación",
            "El premio es demasiado alto",
            "Ganaste un premio en un sorteo en el que nunca participaste",
            "El mensaje llegó por SMS y no por correo",
        ],
        "correct_answer": 2,
        "explanation": (
            "No se puede ganar un sorteo en el que no participaste. "
            "Esta es la señal más clara de fraude. Además, ningún concurso legítimo "
            "pide tus datos bancarios para entregar un premio."
        ),
    },
    {
        "id": 3,
        "scenario": "🔗 Enlace sospechoso",
        "question": (
            "Recibes un correo supuestamente del SENA con un enlace. "
            "¿Cuál de estas direcciones es la OFICIAL y segura?"
        ),
        "options": [
            "http://sena-colombia.net/cursos",
            "https://sena.edu.co/cursos",
            "http://sena-virtual.xyz/acceso",
            "https://sena-oficial.com/login",
        ],
        "correct_answer": 1,
        "explanation": (
            "El sitio oficial del SENA es 'sena.edu.co'. "
            "Los dominios '.net', '.xyz' y '.com' con el nombre de la entidad "
            "son señales de sitios falsos. Además, los sitios seguros usan 'https://'."
        ),
    },
    {
        "id": 4,
        "scenario": "📞 Llamada inesperada",
        "question": (
            "Alguien te llama diciendo ser de Microsoft y que tu computador tiene virus. "
            "Te piden acceso remoto para 'arreglarlo'. ¿Qué haces?"
        ),
        "options": [
            "Darles acceso, ellos son expertos en computadores",
            "Colgar inmediatamente, es una estafa conocida",
            "Pedirles que esperen mientras prendes el computador",
            "Darles tus datos personales para que verifiquen tu identidad",
        ],
        "correct_answer": 1,
        "explanation": (
            "Este es el famoso fraude de 'soporte técnico falso'. "
            "Microsoft, Google y otras empresas tecnológicas NUNCA llaman sin que tú lo solicites. "
            "Cuelga de inmediato. Si tienes dudas, llama tú a los números oficiales."
        ),
    },
    {
        "id": 5,
        "scenario": "📧 Correo con archivo adjunto",
        "question": (
            "Recibes un correo de un remitente desconocido con asunto 'Factura pendiente' "
            "y un archivo adjunto llamado 'factura.pdf.exe'. ¿Qué debes hacer?"
        ),
        "options": [
            "Abrir el archivo, seguramente es una factura real",
            "No abrir el archivo y eliminar el correo",
            "Abrir el archivo pero con cuidado",
            "Reenviar el archivo a un amigo para que lo revise",
        ],
        "correct_answer": 1,
        "explanation": (
            "Un archivo '.exe' disfrazado de PDF es un virus. "
            "Nunca abras archivos adjuntos de remitentes desconocidos, "
            "especialmente si el nombre del archivo tiene dos extensiones (como .pdf.exe). "
            "Elimina el correo de inmediato."
        ),
    },
    {
        "id": 6,
        "scenario": "🏛️ Mensaje del gobierno",
        "question": (
            "Recibes un mensaje: 'DIAN URGENTE: Usted tiene una deuda de $890.000. "
            "Si no paga en 2 horas se iniciará proceso judicial. Pague aquí: bit.ly/dian-pago'. "
            "¿Qué indica que esto es falso?"
        ),
        "options": [
            "La DIAN nunca cobra impuestos",
            "La DIAN no usa mensajes de texto ni crea urgencia artificial",
            "El monto es demasiado pequeño para ser real",
            "Los mensajes del gobierno siempre llegan por carta",
        ],
        "correct_answer": 1,
        "explanation": (
            "La DIAN y otras entidades oficiales no notifican deudas por SMS con enlaces de pago urgentes. "
            "La presión de '2 horas' y el enlace acortado 'bit.ly' son señales claras de estafa. "
            "Si tienes dudas sobre deudas con la DIAN, visita su sitio oficial: dian.gov.co."
        ),
    },
    {
        "id": 7,
        "scenario": "🔐 Seguridad de contraseñas",
        "question": (
            "Alguien que dice ser de 'soporte técnico' de tu correo te llama "
            "y te pide tu contraseña para 'verificar tu cuenta'. ¿Qué haces?"
        ),
        "options": [
            "Darles la contraseña, ellos necesitan verificar",
            "Darles solo los primeros 3 caracteres de la contraseña",
            "Negarte: ningún servicio legítimo pide tu contraseña",
            "Cambiar la contraseña y luego dársela",
        ],
        "correct_answer": 2,
        "explanation": (
            "Ningún servicio legítimo (correo, banco, gobierno) jamás te pedirá tu contraseña. "
            "El soporte técnico real puede ayudarte a cambiarla, pero nunca necesita conocerla. "
            "Si alguien te la pide, es una estafa."
        ),
    },
    {
        "id": 8,
        "scenario": "📲 Redes sociales",
        "question": (
            "Un amigo en Facebook te manda un mensaje: 'Mira este video tuyo que está circulando, "
            "haz clic aquí para verlo: bit.ly/video-viral'. ¿Qué debes sospechar?"
        ),
        "options": [
            "Nada, es tu amigo quien lo manda",
            "Que la cuenta de tu amigo fue hackeada y es un enlace malicioso",
            "Que el video es embarazoso y debes verlo rápido",
            "Que es un chiste y puedes hacer clic sin problema",
        ],
        "correct_answer": 1,
        "explanation": (
            "Las cuentas de redes sociales pueden ser hackeadas o clonadas. "
            "Este mensaje es un señuelo clásico para que hagas clic en un enlace malicioso. "
            "Antes de hacer clic, llama o escribe a tu amigo por otro medio para verificar "
            "si realmente te envió ese mensaje."
        ),
    },
]