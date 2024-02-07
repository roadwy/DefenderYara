
rule Trojan_Win32_Killav_FP{
	meta:
		description = "Trojan:Win32/Killav.FP,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 08 00 00 04 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c } //04 00 
		$a_01_1 = {83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca } //01 00 
		$a_01_2 = {4e 36 35 73 50 73 35 6a 42 63 4c 75 50 47 } //01 00  N65sPs5jBcLuPG
		$a_01_3 = {4e 36 35 73 50 73 44 70 53 64 50 58 42 63 4c 75 50 4a 34 } //01 00  N65sPsDpSdPXBcLuPJ4
		$a_01_4 = {4e 35 44 62 4f 4e 39 5a 51 35 31 6f 52 74 50 66 50 36 4c 6f 42 63 4c 75 50 47 } //01 00  N5DbON9ZQ51oRtPfP6LoBcLuPG
		$a_01_5 = {4f 4e 50 64 4f 73 58 70 54 64 57 6b 50 4e 58 62 } //01 00  ONPdOsXpTdWkPNXb
		$a_01_6 = {4f 4e 50 64 4f 74 39 62 52 4e 57 6b 50 4e 58 62 43 47 } //01 00  ONPdOt9bRNWkPNXbCG
		$a_01_7 = {47 4c 50 37 4c 36 7a 6c 52 36 39 58 53 61 62 6b 53 74 48 58 52 36 6d 6b 50 4e 58 62 43 47 } //00 00  GLP7L6zlR69XSabkStHXR6mkPNXbCG
	condition:
		any of ($a_*)
 
}