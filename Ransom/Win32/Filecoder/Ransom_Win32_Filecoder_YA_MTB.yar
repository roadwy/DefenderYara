
rule Ransom_Win32_Filecoder_YA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.YA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 6d 69 6e 69 73 33 27 73 28 52 29 20 52 61 6e 73 6f 6d 69 6e 61 74 6f 72 } //1 Geminis3's(R) Ransominator
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 22 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 22 } //1 encrypted with "military grade"
		$a_01_2 = {64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 74 6f 20 67 65 74 20 6c 6f 73 74 } //1 decryption key to get lost
		$a_01_3 = {4c 65 61 76 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //1 LeaveCriticalSection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}