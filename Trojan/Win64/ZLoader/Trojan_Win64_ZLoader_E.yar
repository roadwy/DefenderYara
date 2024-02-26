
rule Trojan_Win64_ZLoader_E{
	meta:
		description = "Trojan:Win64/ZLoader.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6d 28 72 b3 a3 15 78 e2 91 79 1e ad 31 66 90 01 01 b3 57 28 a4 f5 a5 5e da a1 1b 95 b8 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}