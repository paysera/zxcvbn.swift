
import Foundation

typealias MatcherBlock = (String) -> [Match]

struct UncheckedSendableWrapper<T>: @unchecked Sendable {
    let value: T
}

public struct MatchResources: @unchecked Sendable {
    let dictionaryMatchers: [MatcherBlock]
    let graphs: [String: [String: [String?]]]

    static let shared: Self = MatchResources(dictionaryMatchers: frequencyLists(), graphs: adjacencyGraphs)

    private static func frequencyLists() -> [MatcherBlock] {
        var dictionaryMatchers = [MatcherBlock]()
        let json = FrequencyLists.json
        for (dictName, wordList) in json {
            let rankedDict = buildRankedList((wordList as! [String]))
            dictionaryMatchers.append(buildDictMatcher(dictName, rankedDict: rankedDict))
        }
        return dictionaryMatchers
    }

    static let adjacencyGraphs: [String: [String: [String?]]] = AdjacencyGraphs.json as! [String: [String: [String?]]]

    static func buildRankedList(_ unrankedList: [String]) -> [String: Int] {
        var result = [String: Int]()
        for (i, word) in unrankedList.enumerated() {
            result[word] = i + 1
        }
        return result
    }

    static func buildDictMatcher(_ dictName: String, rankedDict: [String: Int]) -> MatcherBlock {
        { password in
            let matches = dictionaryMatch(password, rankedDict: rankedDict)
            return matches.map { match in
                var match = match
                match.dictionaryName = dictName
                return match
            }
        }
    }

    static func dictionaryMatch(_ password: String, rankedDict: [String: Int]) -> [Match] {
        var result = [Match]()
        let passwordLower = password.lowercased()

        var i = password.startIndex
        while i < password.endIndex {
            var j = i
            while j < password.endIndex {
                let word = String(passwordLower[i...j])
                if let rank = rankedDict[word] {
                    let match = Match(
                        pattern: "dictionary",
                        token: String(password[i...j]),
                        i: i,
                        j: j,
                        matchedWord: word,
                        rank: rank
                    )
                    result.append(match)
                }
                j = password.index(after: j)
            }
            i = password.index(after: i)
        }
        return result
    }
}

public struct Match: Equatable, CustomStringConvertible {
    public var pattern: String
    public var token: String
    public var i: String.Index
    public var j: String.Index
    public var entropy: Double?
    public var cardinality: Double?

    // Dictionary
    var matchedWord: String?
    var dictionaryName: String?
    var rank: Int?
    var baseEntropy: Double?
    var upperCaseEntropy: Double?

    // l33t
    var l33t: Bool = false
    var sub: [String: String] = [:]
    var subDisplay: String = ""
    var l33tEntropy: Double?

    // Spatial
    var graph: String?
    var turns: Int?
    var shiftedCount: Int?

    // Repeat
    var repeatedChar: String?

    // Sequence
    var sequenceName: String?
    var sequenceSpace: Int?
    var ascending: Bool?

    // Date
    var day: Int?
    var month: Int?
    var year: Int?
    var separator: String?

    public var description: String {
        return "Match (pattern:\(pattern), token:\(token), i:\(i), j:\(j))"
    }
}

class Box<Value> {
    var value: Value
    init(_ value: Value) {
        self.value = value
    }
}

public struct Matcher {

    private let dictionaryMatchers: [MatcherBlock]
    private let graphs: [String: [String: [String?]]]
    private var matchers: Box<[MatcherBlock]>

    public init() {
        let resource = MatchResources.shared
        dictionaryMatchers = resource.dictionaryMatchers
        graphs = resource.graphs

        matchers = Box([])
        matchers.value = dictionaryMatchers + [
            l33tMatch,
            digitsMatch,
            yearMatch,
            dateMatch,
            repeatMatch,
            sequenceMatch,
            spatialMatch
        ]
    }

    public var keyboardAverageDegree: Double {
        calculateAverageDegree(graph: graphs["qwerty"]!)
    }
    public var keypadAverageDegree: Double {
        calculateAverageDegree(graph: graphs["keypad"]!)
    }

    public var keyboardStartingPositions: Int {
        graphs["qwerty"]!.count
    }

    public var keypadStartingPositions: Int {
        graphs["keypad"]!.count
    }
}

public extension Matcher {

    func omnimatch(password: String, userInputs: [String]) -> [Match] {
        if !userInputs.isEmpty {
            var rankedUserInputsDict = [String: Int]()
            for i in 0..<userInputs.count {
                rankedUserInputsDict[userInputs[i].lowercased()] = i + 1
            }
            matchers.value.append(MatchResources.buildDictMatcher("user_inputs", rankedDict: rankedUserInputsDict))
        }

        var matches = [Match]()

        for block in matchers.value {
            matches.append(contentsOf: block(password))
        }

        return matches.sorted(by: { $0.i == $1.i ? $0.j > $1.j : $0.i < $1.i  })
    }
}

private extension Matcher {

    // returns the list of possible 1337 replacement dictionaries for a given password
    func enumerateL33tSubs(table: [String: [String]]) -> [[String: String]] {
        var subs: [[[String]]] = [[]]

        func dedup(subs: [[[String]]]) -> [[[String]]] {
            var deduped = [[[String]]]()
            var members = [String]()

            for sub in subs {
                let assoc = sub.sorted(by: { $0[0].caseInsensitiveCompare($1[0]) == .orderedAscending })

                var kvs = [String]()
                for kv in assoc {
                    kvs.append(kv.joined(separator: ","))
                }
                let label = kvs.joined(separator: "-")
                if !members.contains(label) {
                    members.append(label)
                    deduped.append(sub)
                }
            }
            return deduped
        }

        var keys = Array(table.keys)

        while keys.count > 0 {
            let firstKey = keys[0]
            let restKeys = Array(keys.dropFirst())
            var nextSubs = [[[String]]]()

            for l33tChar in (table[firstKey] ?? []) {
                for sub in subs {
                    var dupL33tIndex = -1
                    for i in 0..<sub.count {
                        if sub[i][0] == l33tChar {
                            dupL33tIndex = i
                            break
                        }
                    }

                    if dupL33tIndex == -1 {
                        var subExtension = sub
                        subExtension.append([String(l33tChar), firstKey])
                        nextSubs.append(subExtension)
                    } else {
                        var subAlternative = sub
                        subAlternative.remove(at: dupL33tIndex)
                        subAlternative.append([String(l33tChar), firstKey])
                        nextSubs.append(sub)
                        nextSubs.append(subAlternative)
                    }
                }
            }

            subs = dedup(subs: nextSubs)
            keys = restKeys
        }

        // Convert from assoc lists to dicts
        var subDicts = [[String: String]]()
        for sub in subs {
            var subDict = [String: String]()
            for pair in sub {
                subDict[pair[0]] = pair[1]
            }

            subDicts.append(subDict)
        }

        return subDicts
    }

    // makes a pruned copy of l33t_table that only includes password's possible substitutions
    func relevantL33tSubtable(for password: String) -> [String: [String]] {
        var filtered = [String: [String]]()

        for letter in Self.l33tTable.keys {
            let subs = Self.l33tTable[letter]!
            var relevantSubs = [String]()

            for sub in subs {
                if password.contains(sub) {
                    relevantSubs.append(sub)
                }
            }
            if !relevantSubs.isEmpty {
                filtered[String(letter)] = relevantSubs
            }
        }
        return filtered
    }

    func l33tMatch(_ password: String) -> [Match] {
        var matches = [Match]()

        for sub in enumerateL33tSubs(table: relevantL33tSubtable(for: password)) {
            if sub.isEmpty {
                break
            }

            let subbedPassword = translate(password, characterMap: sub)

            for matcher in dictionaryMatchers {
                for match in matcher(subbedPassword) {
                    // Cannot use String.Index from subbedPassword on original password
                    // because they may have different internal encodings (UTF-16 vs UTF-8).
                    // Convert to character offsets which are encoding-independent.
                    let iOffset = subbedPassword.distance(from: subbedPassword.startIndex, to: match.i)
                    let jOffset = subbedPassword.distance(from: subbedPassword.startIndex, to: match.j)

                    // Recreate indices in original password using character offsets
                    guard
                        let originalI = password.index(password.startIndex, offsetBy: iOffset, limitedBy: password.endIndex),
                        let originalJ = password.index(password.startIndex, offsetBy: jOffset, limitedBy: password.endIndex),
                        originalI <= originalJ
                    else {
                        continue
                    }

                    let token = password[originalI...originalJ]

                    // only return the matches that contain an actual substitution
                    if token.lowercased() == match.matchedWord {
                        continue
                    }

                    var matchSub = [String: String]()
                    var subDisplay = [String]()

                    for (subbedChar, char) in sub {
                        if token.contains(subbedChar) {
                            matchSub[subbedChar] = char
                            subDisplay.append("\(subbedChar) -> \(char)")
                        }
                    }

                    var match = match

                    match.l33t = true
                    match.token = String(token)
                    match.sub = matchSub
                    match.subDisplay = subDisplay.joined(separator: ",")
                    match.i = originalI
                    match.j = originalJ
                    matches.append(match)
                }
            }

        }

        return matches
    }

    func translate(_ string: String, characterMap: [String: String]) -> String {
        var string = string
        for (key, value) in characterMap {
            string = string.replacingOccurrences(of: key, with: value)
        }
        return string
    }

    static var l33tTable: [String: [String]] {
        [
        "a": ["4", "@"],
        "b": ["8"],
        "c": ["(", "{", "[", "<"],
        "e": ["3"],
        "g": ["6", "9"],
        "i": ["1", "!", "|"],
        "l": ["1", "|", "7"],
        "o": ["0"],
        "s": ["$", "5"],
        "t": ["+", "7"],
        "x": ["%"],
        "z": ["2"]
        ]
    }
}

private extension Matcher {
    func spatialMatch(_ password: String) -> [Match] {
        var matches = [Match]()
        for (graphName, graph) in graphs {
            matches.append(contentsOf: spatialMatchHelper(password, graph: graph, graphName: graphName))
        }
        return matches
    }

    func spatialMatchHelper(_ password: String, graph: [String: [String?]], graphName: String) -> [Match] {
        var result = [Match]()
        var i = password.startIndex
        while (i < password.index(password.endIndex, offsetBy: -1, limitedBy: password.startIndex) ?? password.endIndex) && !password.isEmpty {
            var j = password.index(after: i)
            var lastDirection = -1
            var turns = 0
            var shiftedCount = 0

            while true {
                let prevChar = String(password[password.index(before: j)])
                var found = false
                var foundDirection = -1
                var curDirection = -1
                let adjacents = graph[prevChar] ?? []

                // consider growing pattern by one character if j hasn't gone over the edge.
                if j < password.endIndex {
                    let curChar = String(password[j])
                    for adj in adjacents {
                        curDirection += 1
                        if let adj = adj, adj.contains(curChar) {
                            found = true
                            foundDirection = curDirection
                            if adj.range(of: curChar)?.lowerBound == adj.index(adj.startIndex, offsetBy: 1) {
                                // index 1 in the adjacency means the key is shifted, 0 means unshifted: A vs a, % vs 5, etc.
                                // for example, 'q' is adjacent to the entry '2@'. @ is shifted w/ index 1, 2 is unshifted.
                                shiftedCount += 1
                            }
                            if lastDirection != foundDirection {
                                // adding a turn is correct even in the initial case when lastDirection is -1:
                                // every spatial pattern starts with a turn.
                                turns += 1
                                lastDirection = foundDirection
                            }
                            break
                        }
                    }
                }

                // if the current pattern continued, extend j and try to grow again
                if found {
                    j = password.index(after: j)
                    // otherwise push the pattern discovered so far, if any...
                } else {
                    // don't consider length 1 or 2 chains.
                    if password.distance(from: i, to: j) > 2 {
                        let match = Match(
                            pattern: "spatial",
                            token: String(password[i..<j]),
                            i: i,
                            j: password.index(before: j),
                            graph: graphName,
                            turns: turns,
                            shiftedCount: shiftedCount
                        )
                        result.append(match)
                    }

                    i = j
                    break
                }

            }
        }
        return result
    }
}

private extension Matcher {
    func repeatMatch(_ password: String) -> [Match] {
        var result = [Match]()
        var i = password.startIndex
        while i < password.endIndex {
            var j = password.index(after: i)
            while true {
                let prevChar = String(password[password.index(before: j)])
                let curChar = j < password.endIndex ? String(password[j]) : ""

                if prevChar == curChar {
                    j = password.index(after: j)
                } else {
                    // don't consider length 1 or 2 chains.
                    if password[i..<j].count > 2 {
                        let match = Match(
                            pattern: "repeat",
                            token: String(password[i..<j]),
                            i: i,
                            j: password.index(before: j),
                            repeatedChar: String(password[i])
                        )
                        result.append(match)
                    }

                    i = j
                    break
                }
            }
        }
        return result
    }
}

private extension Matcher {
    func sequenceMatch(_ password: String) -> [Match] {
        let sequences = [
            "lower": "abcdefghijklmnopqrstuvwxyz",
            "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "digits": "01234567890",
        ]

        var result = [Match]()

        var i = password.startIndex
        while i < password.endIndex {
            var j = password.index(after: i)
            var seq: String?
            var seqName: String?
            var seqDirection = 0

            for (seqCandidateName, seqCandidate) in sequences {
                if let iIndex = seqCandidate.firstIndex(of: password[i]),
                   j < password.endIndex,
                   let jIndex = seqCandidate.firstIndex(of: password[j]) {
                    
                    let iN = seqCandidate.distance(from: seqCandidate.startIndex, to: iIndex)
                    let jN = seqCandidate.distance(from: seqCandidate.startIndex, to: jIndex)
                    
                    let direction = jN - iN
                    if direction == 1 || direction == -1 {
                        seq = seqCandidate
                        seqName = seqCandidateName
                        seqDirection = direction
                        break
                    }
                }
            }
            if let seq {
                while true {
                    let prevChar = String(password[password.index(before: j)])
                    let curChar = j < password.endIndex ? String(password[j]) : nil
                    
                    if let prevIndex = seq.firstIndex(of: prevChar.first!),
                       let curChar = curChar,
                       let curIndex = seq.firstIndex(of: curChar.first!) {
                        
                        let prevN = seq.distance(from: seq.startIndex, to: prevIndex)
                        let curN = seq.distance(from: seq.startIndex, to: curIndex)
                        
                        if curN - prevN == seqDirection {
                            j = password.index(after: j)
                        } else {
                            break
                        }
                    } else {
                        break
                    }
                }
                
                if password.distance(from: i, to: j) > 2 {
                    let match = Match(
                        pattern: "sequence",
                        token: String(password[i..<j]),
                        i: i,
                        j: password.index(before: j),
                        sequenceName: seqName,
                        sequenceSpace: seq.count,
                        ascending: seqDirection == 1
                    )
                    result.append(match)
                }
            }
            i = j
        }
        return result
    }

    func findAll(_ password: String, patternName: String, rx: NSRegularExpression) -> [Match] {
        var matches = [Match]()

        for result in rx.matches(in: password, range: NSRange(location: 0, length: password.count)) {
            var match = Match(
                pattern: patternName,
                token: String(password[result.range]),
                i: password.index(password.startIndex, offsetBy: result.range.location),
                j: password.index(password.startIndex, offsetBy: result.range.location + result.range.length - 1)
            )
            if match.pattern == "date" && result.numberOfRanges == 6 {
                guard
                var month = Int(password[result.range(at: 1)]),
                var day = Int(password[result.range(at: 3)]),
                var year = Int(password[result.range(at: 5)])
                else {
                    continue
                }

                match.separator = result.range(at: 2).lowerBound < password.count ? String(password[result.range(at: 2)]) : ""

                // tolerate both day-month and month-day order
                if month >= 12 && month <= 31 && day <= 12 {
                    let temp = day
                    day = month
                    month = temp
                }
                if day > 31 || month > 12 {
                    continue
                }
                if year < 30 {
                    year += 2000
                } else if year < 100 {
                    year += 1900
                }
                match.day = day
                match.month = month
                match.year = year
            }
            matches.append(match)
        }
        return matches
    }

    func digitsMatch(_ password: String) -> [Match] {
        findAll(password, patternName: "digits", rx: try! NSRegularExpression(pattern: "\\d{3,}"))
    }

    func yearMatch(_ password: String) -> [Match] {
        findAll(password, patternName: "year", rx: try! NSRegularExpression(pattern: "19\\d\\d|200\\d|201\\d|202\\d"))
    }

    func dateMatch(_ password: String) -> [Match] {
        findAll(password, patternName: "date", rx: try! NSRegularExpression(pattern: "(\\d{1,2})( |-|\\/|\\.|_)?(\\d{1,2})( |-|\\/|\\.|_)?(19\\d{2}|200\\d|201\\d|202\\d|\\d{2})"))
    }
}

private extension String {
    subscript(_ range: NSRange) -> Substring {
        get {
            self[convert(range: range)]
        }
    }

    func convert(range: NSRange) -> Range<String.Index> {
        index(startIndex, offsetBy: range.lowerBound)..<index(startIndex, offsetBy: range.upperBound)
    }
}

private extension Matcher {
    func calculateAverageDegree(graph: [String: [String?]]) -> Double {
        // on qwerty, 'g' has degree 6, being adjacent to 'ftyhbv'. '\' has degree 1.
        // this calculates the average over all keys.

        var average = 0.0

        for key in graph.keys {
            var neighbors = [String?]()
            for n in (graph[key] ?? []) {
                neighbors.append(n)
            }
            average += Double(neighbors.compactMap { $0 }.count)
        }
        average /= Double(graph.count)
        return average
    }
}
