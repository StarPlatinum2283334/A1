// Модуль анализа стойкости паролей

// БАЗА УТЕКШИХ ПАРОЛЕЙ (топ 100+ распространенных)
function isPasswordCompromised(password) {
    const commonPasswords = [
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
        "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
        "696969", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
        "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
        "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
        "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
        "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
        "klaster", "112233", "george", "computer", "michelle", "1212", "pepper", "11111",
        "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie",
        "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer",
        "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees",
        "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "parol", "пароль", "admin"
    ];
    return commonPasswords.includes(password.toLowerCase());
}

// Определение размера алфавита (L)
function getCharsetSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/[а-яё]/.test(password)) size += 33;
    if (/[А-ЯЁ]/.test(password)) size += 33;
    if (/\d/.test(password)) size += 10;
    if (/[^a-zA-Zа-яА-ЯёЁ0-9]/.test(password)) size += 32;
    return size > 0 ? size : 1;
}

// Расчет энтропии
function calculateEntropy(password) {
    return Math.log2(getCharsetSize(password)) * password.length;
}

// Расчет времени взлома для трех сценариев
function estimateCrackTime(password) {
    const L = getCharsetSize(password);
    const N = password.length;
    const combinations = Math.pow(L, N);
    
    const scenarios = [
        { name: "ПЕРСОНАЛЬНЫЙ КОМПЬЮТЕР (GPU)", speed: 1e9 },
        { name: "РАСПРЕДЕЛЁННАЯ СЕТЬ (БОТНЕТ)", speed: 1e12 },
        { name: "МОЩНАЯ ХАКЕРСКАЯ ИНФРАСТРУКТУРА", speed: 1e15 }
    ];
    
    function formatTime(seconds) {
        if (seconds < 1) return "МГНОВЕННО";
        if (seconds < 60) return `${Math.round(seconds)} СЕКУНД`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} МИНУТ`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} ЧАСОВ`;
        if (seconds < 2592000) return `${Math.round(seconds / 86400)} ДНЕЙ`;
        if (seconds < 31536000) return `${Math.round(seconds / 2592000)} МЕСЯЦЕВ`;
        if (seconds < 315360000) return `${Math.round(seconds / 31536000)} ЛЕТ`;
        return "СОТНИ ТЫСЯЧ ЛЕТ";
    }
    
    return scenarios.map(s => ({
        name: s.name,
        time: formatTime(combinations / s.speed)
    }));
}

// Обнаружение паттернов
function detectPatterns(password) {
    const warnings = [];
    const lower = password.toLowerCase();
    
    if (/123456|12345|1234|123|987654|654321/.test(password)) 
        warnings.push('ЧИСЛОВАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ');
    if (/qwerty|йцукен|asdfgh|фывапр|zxcvbn|ячсми|1qaz/.test(lower)) 
        warnings.push('КЛАВИАТУРНАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ');
    if (/abcdef|bcdefg|cdefgh|defghi|efghij|fghijk|ghijkl|hijklm|ijklmn|jklmno|klmnop|lmnopq|mnopqr|nopqrs|opqrst|pqrstu|qrstuv|rstuvw|stuvwx|tuvwxy|uvwxyz/.test(lower)) 
        warnings.push('АЛФАВИТНАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ');
    if (/(.)\1{2,}/.test(password)) 
        warnings.push('ПОВТОРЯЮЩИЕСЯ СИМВОЛЫ');
    
    const commonWords = ['password', 'parol', 'пароль', 'admin', 'user', 'login', 'welcome', 'master'];
    for (const word of commonWords) {
        if (lower.includes(word)) {
            warnings.push(`РАСПРОСТРАНЁННОЕ СЛОВО: ${word.toUpperCase()}`);
            break;
        }
    }
    return warnings;
}

// ОСНОВНАЯ ФУНКЦИЯ АНАЛИЗА
function analyzePassword(password) {
    let score = 5;
    const recommendations = [];
    let warnings = [];
    
    // 1. Проверка длины
    if (password.length < 8) {
        score -= 3;
        recommendations.push('УВЕЛИЧЬТЕ ДЛИНУ ДО 8+ СИМВОЛОВ');
    } else if (password.length < 12) {
        score += 1;
        recommendations.push('РЕКОМЕНДУЕМАЯ ДЛИНА: 12+ СИМВОЛОВ');
    } else if (password.length >= 16) {
        score += 2;
    }
    
    // 2. Проверка разнообразия символов
    let categoryCount = 0;
    if (/[a-zа-яё]/.test(password)) categoryCount++;
    else recommendations.push('ДОБАВЬТЕ СТРОЧНЫЕ БУКВЫ');
    
    if (/[A-ZА-ЯЁ]/.test(password)) categoryCount++;
    else recommendations.push('ДОБАВЬТЕ ЗАГЛАВНЫЕ БУКВЫ');
    
    if (/\d/.test(password)) categoryCount++;
    else recommendations.push('ДОБАВЬТЕ ЦИФРЫ');
    
    if (/[^a-zA-Zа-яА-ЯёЁ0-9]/.test(password)) categoryCount++;
    else recommendations.push('ДОБАВЬТЕ СПЕЦИАЛЬНЫЕ СИМВОЛЫ');
    
    score += categoryCount;
    
    // 3. Проверка по словарю утекших (КЛЮЧЕВОЙ МОМЕНТ)
    if (isPasswordCompromised(password)) {
        score -= 5;
        warnings.push('КРИТИЧЕСКАЯ УГРОЗА: ПАРОЛЬ НАЙДЕН В БАЗЕ УТЕКШИХ ДАННЫХ!');
        recommendations.push('НЕМЕДЛЕННО СМЕНИТЕ ЭТОТ ПАРОЛЬ');
    }
    
    // 4. Проверка паттернов
    const patternWarnings = detectPatterns(password);
    warnings = [...warnings, ...patternWarnings];
    score -= patternWarnings.length * 2;
    
    // 5. Корректировка по энтропии
    const entropy = calculateEntropy(password);
    if (entropy < 30) score -= 2;
    else if (entropy < 50) score += 1;
    else if (entropy < 70) score += 2;
    else score += 3;
    
    score = Math.min(10, Math.max(0, score));
    
    // 6. Время взлома
    const crackTimes = estimateCrackTime(password);
    
    // 7. Определение уровня стойкости
    let strengthLevel, strengthClass;
    if (isPasswordCompromised(password)) {
        strengthLevel = 'КРИТИЧЕСКИ УЯЗВИМ (ПАРОЛЬ СКОМПРОМЕТИРОВАН)';
        strengthClass = 'danger';
    } else if (score <= 3) {
        strengthLevel = 'КРИТИЧЕСКИ УЯЗВИМ';
        strengthClass = 'danger';
    } else if (score <= 5) {
        strengthLevel = 'НИЗКАЯ СТОЙКОСТЬ';
        strengthClass = 'warning';
    } else if (score <= 7) {
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
        length: password.length,
        entropy: Math.round(entropy * 10) / 10,
        charsetSize: getCharsetSize(password),
        crackTimes
    };
}
'''
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { analyzePassword, getCharsetSize, calculateEntropy, estimateCrackTime };
}
