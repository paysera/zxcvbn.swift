import Foundation

public struct Score {
    public let password: String
    public let entropy: String
    public let crackTime: Double
    public let crackTimeDisplay: String
    public let value: Int
    public let matchSequence: [Match]
    public var calcTime: Double?
}

public struct Scorer {
    public func minimumEntropyMatch(password: String, matches: [Match]) -> Score {
        let bruteforceCardinality = calculateBruteforceCardinality(password: password)
        var upToK = [String.Index: Double]()
        var backpointers = [String.Index: Match?]()

        var matches = matches
        var k = password.startIndex
        while k < password.endIndex {
            if let indexBeforeK = password.index(k, offsetBy: -1, limitedBy: password.startIndex) {
                upToK[k] = upToK[indexBeforeK, default: 0] + log2(bruteforceCardinality)
            } else {
                upToK[k] = 0 + log2(bruteforceCardinality)
            }
            backpointers[k] = nil

            var modifiedMatches = matches
            for (i, match) in matches.enumerated() {
                if match.j != k {
                    continue
                }

                var match = match
                // see if best entropy up to i-1 + entropy of this match is less than the current minimum at j.
                let candidateEntropy: Double
                if let indexBeforeI = password.index(match.i, offsetBy: -1, limitedBy: password.startIndex) {
                    candidateEntropy = upToK[indexBeforeI, default: 0] + calcEntropy(&match)
                } else {
                    candidateEntropy = 0 + calcEntropy(&match)
                }
                modifiedMatches[i] = match
                if candidateEntropy < upToK[match.j, default: 0] {
                    upToK[match.j] = candidateEntropy
                    backpointers[match.j] = match
                }
            }
            matches = modifiedMatches

            k = password.index(after: k)
        }

        var matchSequence = [Match]()
        k = password.endIndex

        while k >= password.startIndex {
            if let match = backpointers[k] as? Match {
                matchSequence.append(match)
                if let indexBeforeI = password.index(match.i, offsetBy: -1, limitedBy: password.startIndex) {
                    k = indexBeforeI
                } else {
                    break
                }
            } else {
                if let indexBeforeK = password.index(k, offsetBy: -1, limitedBy: password.startIndex) {
                    k = indexBeforeK
                } else {
                    break
                }
            }
        }

        matchSequence.reverse()

        func makeBruteforceMatch(_ i: String.Index, _ j: String.Index) -> Match {
            let token = String(password[i..<j])

            return Match(
                pattern: "bruteforce",
                token: token,
                i: i,
                j: j,
                entropy: log2(pow(bruteforceCardinality, Double(token.count))),
                cardinality: bruteforceCardinality
            )
        }

        k = password.startIndex

        var matchSequenceCopy = [Match]()

        for match in matchSequence {
            if match.i > k {
                matchSequenceCopy.append(makeBruteforceMatch(k, password.index(before: match.i)))
            }
            k = password.index(after: match.j)
            matchSequenceCopy.append(match)
        }
        if k < password.endIndex {
            matchSequenceCopy.append(makeBruteforceMatch(k, password.endIndex))
        }

        var minEntropy = 0.0

        if !password.isEmpty {
            minEntropy = upToK[password.index(before: password.endIndex), default: 0]
        }

        let crackTime = entropyToCrackTime(minEntropy)

        return Score(
            password: password,
            entropy: roundToXDigits(minEntropy, digits: 3),
            crackTime: crackTime,
            crackTimeDisplay: displayTime(crackTime),
            value: crackTimeToScore(crackTime),
            matchSequence: matchSequence
        )
    }
}

private extension Scorer {
    /*
    threat model -- stolen hash catastrophe scenario
    assumes:
    * passwords are stored as salted hashes, different random salt per user.
      (making rainbow attacks infeasable.)
    * hashes and salts were stolen. attacker is guessing passwords at max rate.
    * attacker has several CPUs at their disposal.
    * for a hash function like bcrypt/scrypt/PBKDF2, 10ms per guess is a safe lower bound.
    * (usually a guess would take longer -- this assumes fast hardware and a small work factor.)
    * adjust for your site accordingly if you use another hash function, possibly by
    * several orders of magnitude!
    */
    func entropyToCrackTime(_ entropy: Double) -> Double {
        let singleGuess = 0.01
        let numAttackers = 100.0

        let secondsPerGuess = singleGuess / numAttackers
        return pow(2, entropy) * secondsPerGuess / 2
    }

    func calculateBruteforceCardinality(password: String) -> Double {
        var digits = 0.0
        var upper = 0.0
        var lower = 0.0
        var symbols = 0.0

        password.utf8.forEach { char in
            let scalar = Unicode.Scalar(char)
            if CharacterSet.decimalDigits.contains(scalar) {
                digits = 10
            } else if CharacterSet.uppercaseLetters.contains(scalar) {
                upper = 26
            } else if CharacterSet.lowercaseLetters.contains(scalar) {
                lower = 26
            } else {
                symbols = 33
            }
        }

        return digits + upper + lower + symbols
    }

    func calcEntropy(_ match: inout Match) -> Double {
        if let entropy = match.entropy, entropy > 0 {
            return entropy
        }

        if match.pattern == "repeat" {
            match.entropy = repeatEntropy(match)
        } else if match.pattern == "sequence" {
            match.entropy = sequenceEntropy(match)
        } else if match.pattern == "digits" {
            match.entropy = digitsEntropy(match)
        } else if match.pattern == "year" {
            match.entropy = yearEntropy(match)
        } else if match.pattern == "date" {
            match.entropy = dateEntropy(match)
        } else if match.pattern == "spatial" {
            match.entropy = spatialEntropy(match)
        } else if match.pattern == "dictionary" {
            match.entropy = dictionaryEntropy(&match)
        }

        return match.entropy ?? 0
    }

    func roundToXDigits(_ number: Double, digits: Int) -> String {
        String(number.rounded(toPlaces: digits))
    }

    func displayTime(_ seconds: Double) -> String {
        let minute = 60.0
        let hour = minute * 60.0
        let day = hour * 24.0
        let month = day * 31.0
        let year = month * 12.0
        let century = year * 100.0
        if seconds < minute {
            return "instant"
        }
        if seconds < hour {
            return "\(1 + Int(ceil(seconds / minute))) minutes"
        }
        if seconds < day {
            return "\(1 + Int(ceil(seconds / hour))) hours"
        }
        if seconds < month {
            return "\(1 + Int(ceil(seconds / day))) days"
        }
        if seconds < year {
            return "\(1 + Int(ceil(seconds / month))) months"
        }
        if seconds < century {
            return "\(1 + Int(ceil(seconds / year))) years"
        }
        return "centuries"
    }

    func crackTimeToScore(_ seconds: Double) -> Int {
        if seconds < pow(10, 2) {
            return 0
        }
        if seconds < pow(10, 4) {
            return 1
        }
        if seconds < pow(10, 6) {
            return 2
        }
        if seconds < pow(10, 8) {
            return 3
        }
        return 4
    }
}

private extension Scorer {
    func repeatEntropy(_ match: Match) -> Double {
        let cardinality = calculateBruteforceCardinality(password: match.token)
        return log2(cardinality * Double(match.token.count))
    }
    func sequenceEntropy(_ match: Match) -> Double {
        let firstChar = match.token[match.token.startIndex]
        var baseEntropy = 0.0
        if ["a", "1"].contains(firstChar) {
            baseEntropy = 1
        } else {
            let chr = Unicode.Scalar(match.token.utf8[match.token.startIndex])
            if CharacterSet.decimalDigits.contains(chr) {
                baseEntropy = log2(10)
            } else if CharacterSet.lowercaseLetters.contains(chr) {
                baseEntropy = log2(26)
            } else {
                baseEntropy = log2(26) + 1
            }
        }
        if !(match.ascending == true) {
            baseEntropy += 1
        }

        return baseEntropy + log2(Double(match.token.count))
    }
    func digitsEntropy(_ match: Match) -> Double {
        return log2(pow(10, Double(match.token.count)))
    }
    static let numYears = 129.0 // years match against 1900 - 2029
    static let numMonths = 12.0
    static let numDays = 31.0

    func yearEntropy(_ match: Match) -> Double {
        return log2(Self.numYears)
    }

    func dateEntropy(_ match: Match) -> Double {
        var entropy = 0.0
        if (match.year ?? Int.max) < 100 {
            entropy = log2(Self.numDays * Self.numMonths * 100) // Two digit year
        } else {
            entropy = log2(Self.numDays * Self.numMonths * Self.numYears) // Four digit year
        }

        if (match.separator?.count ?? 0) > 0 {
            entropy += 2 // add two bits for separator selection [/,-,.,etc]
        }

        return entropy
    }

    func spatialEntropy(_ match: Match) -> Double {
        let matcher = Matcher()
        let s: Int
        let d: Int
        if ["qwerty", "dvorak"].contains(match.graph) {
            s = matcher.keyboardStartingPositions
            d = Int(matcher.keyboardAverageDegree)
        } else {
            s = matcher.keypadStartingPositions
            d = Int(matcher.keypadAverageDegree)
        }
        var possibilities = 0
        let L = match.token.count
        let t = match.turns ?? 0
        // Estimate the number of possible patterns w/ length L or less with t turns or less.
        for i in 2...L {
            let possibleTurns = min(t, i - 1)
            for j in 1...possibleTurns {
                possibilities += Int(binom(i - 1, j - 1)) * s * Int(pow(Double(d), Double(j)))
            }
        }
        var entropy = log2(Double(possibilities))
        // add extra entropy for shifted keys. (% instead of 5, A instead of a.)
        // math is similar to extra entropy from uppercase letters in dictionary matches.

        if let shiftedCount = match.shiftedCount, shiftedCount > 0 {
            let S = shiftedCount
            let U = match.token.count - shiftedCount
            var possibilities = 0
            for i in 0...min(S, U) {
                possibilities += Int(binom(S + U, i))
            }
            entropy += log2(Double(possibilities))
        }

        return entropy
    }

    func binom(_ n: Int, _ k: Int) -> Double {
        if k > n {
            return 0
        }
        if k == 0 {
            return 1
        }
        var result = 1.0
        var nDouble = Double(n)
        for denom in 1...k {
            result *= nDouble
            result /= Double(denom)
            nDouble -= 1
        }
        return result
    }

    func dictionaryEntropy(_ match: inout Match) -> Double {
        match.baseEntropy = log2(Double(match.rank ?? 0))
        match.upperCaseEntropy = extraUppercaseEntropy(match)
        match.l33tEntropy = extraL33tEntropy(match)
        let result = (match.baseEntropy ?? 0) + (match.upperCaseEntropy ?? 0) + (match.l33tEntropy ?? 0)
        return result
    }

    func extraUppercaseEntropy(_ match: Match) -> Double {
        let word = match.token

        if CharacterSet.uppercaseLetters.isDisjoint(with: CharacterSet(charactersIn: word)) {
            return 0
        }

        // a capitalized word is the most common capitalization scheme,
        // so it only doubles the search space (uncapitalized + capitalized): 1 extra bit of entropy.
        // allcaps and end-capitalized are common enough too, underestimate as 1 extra bit to be safe.

        let startUpper = "^[A-Z][^A-Z]+$"
        let endUpper = "^[^A-Z]+[A-Z]$"
        let allUpper = "^[A-Z]+$"

        for regex in [startUpper, endUpper, allUpper] {
            if (try! NSRegularExpression(pattern: regex).firstMatch(in: word, range: NSRange(location: 0, length: word.count))) != nil {
                return 1
            }
        }

        // otherwise calculate the number of ways to capitalize U+L uppercase+lowercase letters with U uppercase letters or less.
        // or, if there's more uppercase than lower (for e.g. PASSwORD), the number of ways to lowercase U+L letters with L lowercase letters or less.

        var uppercaseLength = 0
        var lowercaseLength = 0
        for c in word.utf8 {
            let chr = Unicode.Scalar(c)
            if CharacterSet.uppercaseLetters.contains(chr) {
                uppercaseLength += 1
            } else if CharacterSet.lowercaseLetters.contains(chr)  {
                lowercaseLength += 1
            }
        }

        var possibilities = 0.0
        for i in 0...min(uppercaseLength, lowercaseLength) {
            possibilities += binom(uppercaseLength + lowercaseLength, i)
        }

        return log2(possibilities)
    }

    func extraL33tEntropy(_ match: Match) -> Double {
        guard match.l33t else {
            return 0
        }

        var possibilities = 0.0

        for (subbed, unsubbed) in match.sub {
            let subLength = match.token.components(separatedBy: subbed).count - 1
            let unsubLength = match.token.components(separatedBy: unsubbed).count - 1

            for i in 0...min(subLength, unsubLength) {
                possibilities += binom(subLength + unsubLength, i)
            }
        }

        return possibilities <= 1 ? 1 : log2(possibilities)
    }
}

extension Double {
    func rounded(toPlaces places: Int) -> Double {
        let divisor = pow(10.0, Double(places))
        return (self * divisor).rounded() / divisor
    }
}
