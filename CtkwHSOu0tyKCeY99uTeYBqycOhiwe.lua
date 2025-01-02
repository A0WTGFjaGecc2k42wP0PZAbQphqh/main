local EncryptionService = {}

-- Constants for printable ASCII range
local PRINTABLE_ASCII_MIN: number = 32 -- Space character
local PRINTABLE_ASCII_MAX: number = 126 -- Tilde character

-- ROT13 Encoding/Decoding
local ROT13_A: number = 65
local ROT13_Z: number = 90
local ROT13_a: number = 97
local ROT13_z: number = 122
local ROT13_MOD: number = 26

-- Base64 Encoding/Decoding
local B64Chars: string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64INV: {[string]: number} = {}

--[[
    Checks if a given byte represents a printable ASCII character.
    @param Byte number The byte value to check.
    @return boolean True if the byte is within the printable ASCII range, false otherwise.
--]]
local function IsPrintableAscii(Byte: number): boolean
	return Byte >= PRINTABLE_ASCII_MIN and Byte <= PRINTABLE_ASCII_MAX
end

--[[
    Encrypts a string using XOR encryption.
    @param Text string The text to be encrypted.
    @param Key string The encryption key.
    @return string The encrypted text.
    @throws Error If either text or key is not a string.
--]]
function EncryptionService:XorEncrypt(Text: string, Key: string): string
	assert(type(Text) == "string" and type(Key) == "string", "Text and key must be strings")
	
	local EncryptedCharacters: {string} = {}
	local KeyLength: number = #Key
	
	for Index = 1, #Text do
		local TextCharacter: number = string.byte(Text, Index)
		local KeyCharacter: number = string.byte(Key, (Index - 1) % KeyLength + 1)
		
		EncryptedCharacters[Index] = string.char(bit32.bxor(TextCharacter, KeyCharacter))
	end
	
	return table.concat(EncryptedCharacters)
end

--[[
    Decrypts a string using XOR decryption. Since XOR is symmetric, this method calls XorEncrypt.
    @param EncryptedText string The text to be decrypted.
    @param Key string The decryption key.
    @return string The decrypted text.
    @throws Error If either text or key is not a string.
--]]
function EncryptionService:XorDecrypt(EncryptedText: string, Key: string): string
	return self:XorEncrypt(EncryptedText, Key) -- XOR is a symmetric operation
end

--[[
    Encrypts a string using a substitution cipher.
    @param Text string The text to be encrypted.
    @param SubstitutionTable {string: string} A table that maps characters to their substituted values.
    @return string The encrypted text.
    @throws Error If text is not a string or substitutionTable is not a table.
--]]
function EncryptionService:SubstitutionEncrypt(Text: string, SubstitutionTable: {string: string}): string
	assert(type(Text) == "string" and type(SubstitutionTable) == "table", "Invalid input types")
	
	local EncryptedCharacters: {string} = {}
	
	for Index = 1, #Text do
		local Character: string = string.sub(Text, Index, Index)
		
		EncryptedCharacters[Index] = SubstitutionTable[Character] or Character
	end
	
	return table.concat(EncryptedCharacters)
end

--[[
    Decrypts a string that was encrypted with substitution cipher
    @param EncryptedText string The encrypted text.
    @param ReverseSubstitutionTable {string: string} A table that maps encrypted characters back to their original values.
    @return string The decrypted text.
     @throws Error If encryptedText is not a string or reverseSubstitutionTable is not a table.
--]]
function EncryptionService:SubstitutionDecrypt(EncryptedText: string, ReverseSubstitutionTable: {string: string}): string
	assert(type(EncryptedText) == "string" and type(ReverseSubstitutionTable) == "table", "Invalid input types")
	
	local DecryptedCharacters: {string} = {}
	
	for Index = 1, #EncryptedText do
		local Character: string = string.sub(EncryptedText, Index, Index)
		
		DecryptedCharacters[Index] = ReverseSubstitutionTable[Character] or Character
	end
	
	return table.concat(DecryptedCharacters)
end

--[[
    Generates a substitution table and its reverse for substitution encryption/decryption.
    @return table SubstitutionTable A table for character substitutions.
    @return table ReverseSubstitutionTable A table for reversing character substitutions.
--]]
function EncryptionService:GenerateSubstitutionTable(): ({string: string}, {string: string})
	local Characters: {string} = {}
	
	for PRINTABLE_NUMBER = PRINTABLE_ASCII_MIN, PRINTABLE_ASCII_MAX do
		Characters[#Characters + 1] = string.char(PRINTABLE_NUMBER)
	end

    --[[
        Shuffles a table in-place using the Fisher-Yates algorithm.
        @param Table {any} The table to be shuffled.
        @return {any} The shuffled table
    --]]
	local function Shuffle(Table: {any}): {any}
		for Number = #Table, 2, -1 do
			local RandomNumber = math.random(Number)
			Table[Number], Table[RandomNumber] = Table[RandomNumber], Table[Number]
		end
		
		return Table
	end

	local ShuffledCharacters: {string} = Shuffle(Characters)

	local SubstitutionTable: {string: string} = {}
	local ReverseSubstitutionTable: {string: string} = {}

	for Index = 1, #Characters do
		local OriginalCharacter: string = string.char(PRINTABLE_ASCII_MIN + (Index - 1))
		local ShuffledCharacter: string = ShuffledCharacters[Index]
		
		SubstitutionTable[OriginalCharacter] = ShuffledCharacter
		ReverseSubstitutionTable[ShuffledCharacter] = OriginalCharacter
	end

	return SubstitutionTable, ReverseSubstitutionTable
end

--[[
    Encrypts a string using the Caesar cipher.
    @param Text string The text to be encrypted.
    @param ShiftNumber number The number of positions to shift each character.
    @return string The encrypted text.
    @throws Error If text is not a string or shift is not a number.
--]]
function EncryptionService:CaesarEncrypt(Text: string, ShiftNumber: number): string
	assert(type(Text) == "string" and type(ShiftNumber) == "number", "Invalid input types")
	
	local EncryptedCharacters: {string} = {}
	
	for Index = 1, #Text do
		local Character: number = string.byte(Text, Index)
		
		if IsPrintableAscii(Character) then
			local EncryptedCharacter: number = (Character - PRINTABLE_ASCII_MIN + ShiftNumber) % 95 + PRINTABLE_ASCII_MIN
			
			EncryptedCharacters[Index] = string.char(EncryptedCharacter)
		else
			EncryptedCharacters[Index] = string.char(Character)
		end
	end
	return table.concat(EncryptedCharacters)
end

--[[
    Decrypts a string using the Caesar cipher.
    @param EncryptedText string The text to be decrypted.
    @param ShiftNumber number The number of positions to shift each character.
    @return string The decrypted text.
     @throws Error If encryptedText is not a string or shift is not a number.
--]]
function EncryptionService:CaesarDecrypt(EncryptedText: string, ShiftNumber: number): string
	return self:CaesarEncrypt(EncryptedText, -ShiftNumber)
end

--[[
    Encrypts a string using the Vigenere cipher.
    @param Text string The text to be encrypted.
    @param Key string The encryption key.
    @return string The encrypted text.
     @throws Error If text or key is not a string.
--]]
function EncryptionService:VigenereEncrypt(Text: string, Key: string): string
	assert(type(Text) == "string" and type(Key) == "string", "Text and key must be strings")
	
	local EncryptedCharacters: {string} = {}
	local KeyLength: number = #Key

	for Index = 1, #Text do
		local TextCharacter: number = string.byte(Text, Index)
		
		if IsPrintableAscii(TextCharacter) then
			local KeyCharacter: number = string.byte(Key, (Index - 1) % KeyLength + 1)
			local EncryptedCharacter: number = (TextCharacter - PRINTABLE_ASCII_MIN + (KeyCharacter - PRINTABLE_ASCII_MIN)) % 95 + PRINTABLE_ASCII_MIN
			
			EncryptedCharacters[Index] = string.char(EncryptedCharacter)
		else
			EncryptedCharacters[Index] = string.char(TextCharacter)
		end
	end
	return table.concat(EncryptedCharacters)
end

--[[
    Decrypts a string using the Vigenere cipher.
    @param EncryptedText string The encrypted text.
    @param Key string The decryption key.
    @return string The decrypted text.
     @throws Error If encryptedText or key is not a string.
--]]
function EncryptionService:VigenereDecrypt(EncryptedText: string, Key: string): string
	assert(type(EncryptedText) == "string" and type(Key) == "string", "Encrypted text and key must be strings")
	local DecryptedCharacters: {string} = {}
	local KeyLength: number = #Key

	for Index = 1, #EncryptedText do
		local EncryptedCharacter: number = string.byte(EncryptedText, Index)
		if IsPrintableAscii(EncryptedCharacter) then
			local KeyCharacter: number = string.byte(Key, (Index - 1) % KeyLength + 1)
			local DecryptedCharacter: number = (EncryptedCharacter - PRINTABLE_ASCII_MIN - (KeyCharacter - PRINTABLE_ASCII_MIN) + 95) % 95 + PRINTABLE_ASCII_MIN
			DecryptedCharacters[Index] = string.char(DecryptedCharacter)
		else
			DecryptedCharacters[Index] = string.char(EncryptedCharacter)
		end
	end
	return table.concat(DecryptedCharacters)
end

--[[
    Checks if a string is valid for encryption (non-empty string).
    @param Text string The string to be validated.
    @return boolean True if the string is valid, false otherwise.
--]]
function EncryptionService:IsValidString(Text: string): boolean
	return type(Text) == "string" and #Text > 0
end

for k = 1, #B64Chars do
	B64INV[string.sub(B64Chars, k, k)] = k - 1
end

B64INV["="] = 0

--[[
    Encodes a string into Base64 format.
    @param Text string The string to be encoded.
    @return string The Base64 encoded string.
    @throws Error If text is not a string.
--]]
function EncryptionService:Base64Encode(Text: string): string
	assert(type(Text) == "string", "Input must be a string")
	
	local Result: {string} = {}
	local Number: number = 1

	while Number <= #Text do
		local Byte1: number = string.byte(Text, Number)
		local Byte2: number = string.byte(Text, Number + 1)
		local Byte3: number = string.byte(Text, Number + 2)

		local Enc1: number = bit32.rshift(Byte1, 2)
		local Enc2: number = bit32.band(bit32.lshift(Byte1, 4), 0x3F) + bit32.rshift(Byte2 or 0, 4)
		local Enc3: number = bit32.band(bit32.lshift(Byte2 or 0, 2), 0x3F) + bit32.rshift(Byte3 or 0, 6)
		local Enc4: number = bit32.band(Byte3 or 0, 0x3F)

		Result[#Result + 1] = string.sub(B64Chars, Enc1 + 1, Enc1 + 1)
		Result[#Result + 1] = string.sub(B64Chars, Enc2 + 1, Enc2 + 1)

		if Byte2 then
			Result[#Result + 1] = string.sub(B64Chars, Enc3 + 1, Enc3 + 1)
		else
			Result[#Result + 1] = "="
		end

		if Byte3 then
			Result[#Result + 1] = string.sub(B64Chars, Enc4 + 1, Enc4 + 1)
		else
			Result[#Result + 1] = "="
		end
		
		Number = Number + 3
	end
	
	return table.concat(Result)
end

--[[
    Decodes a Base64 encoded string.
    @param Text string The Base64 encoded string.
    @return string The decoded string.
    @throws Error If text is not a string.
--]]
function EncryptionService:Base64Decode(Text: string): string
	assert(type(Text) == "string", "Input must be a string")
	local Result: {string} = {}
	local Number: number = 1

	while Number <= #Text do
		local Char1: string = string.sub(Text, Number, Number)
		local Char2: string = string.sub(Text, Number + 1, Number + 1)
		local Char3: string = string.sub(Text, Number + 2, Number + 2)
		local Char4: string = string.sub(Text, Number + 3, Number + 3)

		local Enc1: number = B64INV[Char1]
		local Enc2: number = B64INV[Char2]
		local Enc3: number = B64INV[Char3]
		local Enc4: number = B64INV[Char4]

		local Byte1: number = bit32.band(bit32.lshift(Enc1, 2), 0xFF) + bit32.rshift(Enc2, 4)
		local Byte2: number = bit32.band(bit32.lshift(Enc2, 4), 0xFF) + bit32.rshift(Enc3, 2)
		local Byte3: number = bit32.band(bit32.lshift(Enc3, 6), 0xFF) + Enc4

		Result[#Result + 1] = string.char(Byte1)

		if Char3 ~= "=" then
			Result[#Result + 1] = string.char(Byte2)
		end
		
		if Char4 ~= "=" then
			Result[#Result + 1] = string.char(Byte3)
		end

		Number = Number + 4
	end
	
	return table.concat(Result)
end

--[[
    Encrypts a string using the ROT13 cipher.
    @param Text string The text to be encrypted.
    @return string The encrypted text.
     @throws Error If text is not a string.
--]]
function EncryptionService:ROT13Encrypt(Text: string): string
	assert(type(Text) == "string", "Text must be a string")
	
	local EncryptedCharacters: {string} = {}
	
	for i = 1, #Text do
		local Character: number = string.byte(Text, i)
		
		if Character >= ROT13_A and Character <= ROT13_Z then
			local EncryptedCharacter: number = (Character - ROT13_A + 13) % ROT13_MOD + ROT13_A
			
			EncryptedCharacters[i] = string.char(EncryptedCharacter)
		elseif Character >= ROT13_a and Character <= ROT13_z then
			local EncryptedCharacter: number = (Character - ROT13_a + 13) % ROT13_MOD + ROT13_a
			
			EncryptedCharacters[i] = string.char(EncryptedCharacter)
		else
			EncryptedCharacters[i] = string.char(Character)
		end
	end
	return table.concat(EncryptedCharacters)
end

--[[
    Decrypts a string using the ROT13 cipher.
    @param EncryptedText string The encrypted text.
    @return string The decrypted text.
     @throws Error If encryptedText is not a string.
--]]
function EncryptionService:ROT13Decrypt(EncryptedText: string): string
	return self:ROT13Encrypt(EncryptedText)
end


--[[
    Encrypts a string using the Atbash cipher.
    @param Text string The text to be encrypted.
    @return string The encrypted text.
    @throws Error If text is not a string.
--]]
function EncryptionService:AtbashEncrypt(Text: string): string
	assert(type(Text) == "string", "Text must be a string")

	local EncryptedCharacters: {string} = {}
	
	for i = 1, #Text do
		local charCode: number = string.byte(Text, i)
		if charCode >= 65 and charCode <= 90 then -- Uppercase letters
			EncryptedCharacters[i] = string.char(90 - (charCode - 65))
		elseif charCode >= 97 and charCode <= 122 then -- Lowercase letters
			EncryptedCharacters[i] = string.char(122 - (charCode - 97))
		else
			EncryptedCharacters[i] = string.char(charCode) -- Leave non-alphabetic characters unchanged
		end
	end
	
	return table.concat(EncryptedCharacters)
end


--[[
    Decrypts a string using the Atbash cipher.
    @param EncryptedText string The encrypted text.
    @return string The decrypted text.
     @throws Error If encryptedText is not a string.
--]]
function EncryptionService:AtbashDecrypt(EncryptedText: string): string
	return self:AtbashEncrypt(EncryptedText)
end

--[[
    Encrypts a string using a simple reverse cipher.
    @param Text string The text to be encrypted.
    @return string The encrypted text.
     @throws Error If text is not a string.
--]]
function EncryptionService:ReverseEncrypt(Text: string): string
	assert(type(Text) == "string", "Text must be a string")
	local ReversedText: {string} = {}
	
	for i = #Text, 1, -1 do
		ReversedText[#ReversedText + 1] = string.sub(Text, i, i)
	end
	
	return table.concat(ReversedText)
end

--[[
    Decrypts a string using the reverse cipher. Since its symmetric it just calls the reverse encrypt method.
    @param EncryptedText string The encrypted text.
    @return string The decrypted text.
     @throws Error If encryptedText is not a string.
--]]
function EncryptionService:ReverseDecrypt(EncryptedText: string): string
	return self:ReverseEncrypt(EncryptedText)
end

return EncryptionService
