
rule Trojan_BAT_Keylogger_NKL_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 15 00 00 0a 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 04 00 11 04 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 00 11 05 07 16 07 8e 69 6f ?? 00 00 0a } //5
		$a_01_1 = {46 78 34 62 65 74 61 } //1 Fx4beta
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Keylogger_NKL_MTB_2{
	meta:
		description = "Trojan:BAT/Keylogger.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f ca 00 00 06 2c 06 73 ?? 00 00 0a 7a 03 11 04 1f 50 58 28 ?? 00 00 0a 13 09 03 11 04 1f 54 58 28 ?? 00 00 0a 13 0a 16 } //5
		$a_01_1 = {53 65 63 75 72 65 48 6f 72 69 7a 6f 6e 73 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 SecureHorizons.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Keylogger_NKL_MTB_3{
	meta:
		description = "Trojan:BAT/Keylogger.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f e2 00 00 0a 0b 07 16 73 ?? ?? 00 0a 13 0b 11 0b 73 ?? ?? 00 0a 13 04 7e ?? ?? 00 04 11 04 7e ?? ?? 00 04 11 04 28 ?? ?? 00 06 28 ?? ?? 00 06 13 05 } //5
		$a_01_1 = {41 6e 61 72 63 68 79 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Anarchy.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Keylogger_NKL_MTB_4{
	meta:
		description = "Trojan:BAT/Keylogger.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 24 00 00 0a 02 6f ?? ?? ?? 0a 0a 06 6f ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 17 8d ?? ?? ?? 01 0d 07 6f ?? ?? ?? 0a 8e 69 2d 02 14 0d 07 08 09 6f ?? ?? ?? 0a 26 2a } //5
		$a_03_1 = {73 1f 00 00 0a 0a 28 ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 2a } //5
		$a_01_2 = {6e 30 6c 43 34 35 65 6f 57 67 6a 4f 6c 72 5f } //1 n0lC45eoWgjOlr_
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}