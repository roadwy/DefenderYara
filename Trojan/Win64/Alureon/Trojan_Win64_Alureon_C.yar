
rule Trojan_Win64_Alureon_C{
	meta:
		description = "Trojan:Win64/Alureon.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 6c 73 61 73 68 2e 78 70 00 } //01 00 
		$a_00_1 = {00 63 6d 64 36 34 2e 64 6c 6c 00 } //01 00 
		$a_01_2 = {48 b8 66 69 72 65 66 6f 78 00 48 89 05 } //00 00 
	condition:
		any of ($a_*)
 
}