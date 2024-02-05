
rule Trojan_Win32_Cryptbot_GLM_MTB{
	meta:
		description = "Trojan:Win32/Cryptbot.GLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b9 22 8d 2a 8b 09 20 89 f9 31 39 ab 22 b4 28 2b 33 1d 45 08 e5 31 48 d3 b4 84 b1 28 91 5e 76 51 31 f5 e1 5c } //01 00 
		$a_01_1 = {47 65 74 55 73 65 72 4e 61 6d 65 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00 
		$a_01_4 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}