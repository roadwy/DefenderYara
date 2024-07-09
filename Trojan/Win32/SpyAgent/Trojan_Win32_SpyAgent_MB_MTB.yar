
rule Trojan_Win32_SpyAgent_MB_MTB{
	meta:
		description = "Trojan:Win32/SpyAgent.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {65 78 70 6f 72 74 44 61 74 61 } //1 exportData
		$a_81_1 = {53 74 65 61 6c 65 72 2e 65 78 65 } //1 Stealer.exe
		$a_03_2 = {8a 46 01 8b cf 88 45 0b 8d 45 0b 53 50 e8 ?? ?? ?? ?? 8a 46 02 8b cf 88 45 0b 8d 45 0b 53 50 e8 ?? ?? ?? ?? 8a 46 03 8b cf 88 45 0b 8d 45 0b 53 50 e8 ?? ?? ?? ?? 8a 46 04 8b cf 88 45 0b 8d 45 0b 53 50 e8 } //1
		$a_81_3 = {70 61 73 73 77 6f 72 64 73 } //1 passwords
		$a_81_4 = {63 6f 6f 6b 69 65 73 } //1 cookies
		$a_81_5 = {63 72 79 70 74 6f } //1 crypto
		$a_81_6 = {53 68 69 66 74 4c 65 66 74 } //1 ShiftLeft
		$a_81_7 = {53 68 69 66 74 52 69 67 68 74 } //1 ShiftRight
		$a_81_8 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 57 } //1 HttpOpenRequestW
		$a_81_9 = {55 73 65 72 6e 61 6d 65 3a } //1 Username:
		$a_81_10 = {52 65 61 64 43 6f 6f 6b 69 65 } //1 ReadCookie
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}