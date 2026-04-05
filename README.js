function analyzePasswordStrength(password) {
    let score = 0;
    let feedback = [];

    const length = password.length;

    // Длина
    if (length >= 12) score += 2;
    else if (length >= 8) score += 1;
    else feedback.push("Пароль слишком короткий");

    // Классы символов
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

    const classesCount = [
        /[a-z]/.test(password),
        /[A-Z]/.test(password),
        /[0-9]/.test(password),
        /[^a-zA-Z0-9]/.test(password)
    ].filter(Boolean).length;

    if (classesCount >= 3) score += 2;
    else if (classesCount === 2) score += 1;
    else feedback.push("Используйте разные типы символов");

    // Энтропия
    const entropy = calculateEntropy(password);
    if (entropy > 60) score += 2;
    else if (entropy > 40) score += 1;
    else feedback.push("Низкая энтропия");

    // Паттерны
    if (/123456|password|qwerty/i.test(password)) {
        score -= 2;
        feedback.push("Обнаружен распространённый шаблон");
    }

    // Итоговая оценка
    let strength = "";
    if (score >= 5) strength = "Сильный";
    else if (score >= 3) strength = "Средний";
    else strength = "Слабый";

    return {
        score,
        strength,
        feedback,
        entropy
    };
}
