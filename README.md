# A1
function analyzePassword(password) {
    let score = 0;
    const recommendations = [];
    const warnings = [];
    
    if (password.length < 8) {
        score -= 2;
        recommendations.push('УВЕЛИЧЬТЕ ДЛИНУ ПАРОЛЯ ДО 8+ СИМВОЛОВ');
    } else if (password.length < 12) {
        score += 1;
        recommendations.push('ДЛЯ МАКСИМАЛЬНОЙ БЕЗОПАСНОСТИ ИСПОЛЬЗУЙТЕ 12+ СИМВОЛОВ');
    } else {
        score += 2;
    }
    
    if (/[A-Z]/.test(password)) {
        score += 1;
    } else {
        recommendations.push('ДОБАВЬТЕ ЗАГЛАВНЫЕ БУКВЫ');
    }
    
    if (/[a-z]/.test(password)) {
        score += 1;
    } else {
        recommendations.push('ДОБАВЬТЕ СТРОЧНЫЕ БУКВЫ');
    }
    
    if (/\d/.test(password)) {
        score += 1;
    } else {
        recommendations.push('ДОБАВЬТЕ ЦИФРЫ');
    }
    
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        score += 1;
    } else {
        recommendations.push('ДОБАВЬТЕ СПЕЦИАЛЬНЫЕ СИМВОЛЫ (!@#$%^&*)');
    }
    
    const commonPatterns = [
        { pattern: /123456|12345|1234/, message: 'ОБНАРУЖЕНА ЧИСЛОВАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ' },
        { pattern: /qwerty|asdfgh|zxcvbn/, message: 'ОБНАРУЖЕНА ПОСЛЕДОВАТЕЛЬНОСТЬ КЛАВИШ' },
        { pattern: /password|parol|пароль/, message: 'ОБНАРУЖЕНО ЧАСТО ИСПОЛЬЗУЕМОЕ СЛОВО' },
        { pattern: /(.)\1{2,}/, message: 'ОБНАРУЖЕНЫ ПОВТОРЯЮЩИЕСЯ СИМВОЛЫ' },
        { pattern: /(abc|bcd|cde|def)/, message: 'ОБНАРУЖЕНА АЛФАВИТНАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ' }
    ];
    
    commonPatterns.forEach(item => {
        if (item.pattern.test(password.toLowerCase())) {
            score -= 2;
            warnings.push(item.message);
        }
    });
    
    const charsetSize = calculateCharsetSize(password);
    const possibleCombinations = Math.pow(charsetSize, password.length);
    const timeToCrack = estimateCrackTime(possibleCombinations);
    
    let strengthLevel = '';
    let strengthClass = '';
    
    if (score <= 2) {
        strengthLevel = 'КРИТИЧЕСКИ УЯЗВИМ';
        strengthClass = 'danger';
    } else if (score <= 4) {
        strengthLevel = 'НИЗКАЯ СТОЙКОСТЬ';
        strengthClass = 'warning';
    } else if (score <= 6) {
        strengthLevel = 'СРЕДНЯЯ СТОЙКОСТЬ';
        strengthClass = 'warning';
    } else {
        strengthLevel = 'ВЫСОКАЯ СТОЙКОСТЬ';
        strengthClass = 'success';
    }
    
    return {
        score,
        strengthLevel,
        strengthClass,
        recommendations,
        warnings,
        timeToCrack,
        length: password.length
    };
}
