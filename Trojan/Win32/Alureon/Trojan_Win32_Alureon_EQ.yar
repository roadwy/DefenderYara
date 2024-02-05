
rule Trojan_Win32_Alureon_EQ{
	meta:
		description = "Trojan:Win32/Alureon.EQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 21 43 65 87 c7 44 24 1c 2b 02 00 00 } //01 00 
		$a_01_1 = {53 6a 01 6a 0a ff d6 e8 } //01 00 
		$a_01_2 = {73 70 6f 6f 6c 73 76 2e 65 78 65 00 4c 64 72 41 64 64 52 65 66 44 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}