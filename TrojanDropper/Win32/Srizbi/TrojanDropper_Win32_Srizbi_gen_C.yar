
rule TrojanDropper_Win32_Srizbi_gen_C{
	meta:
		description = "TrojanDropper:Win32/Srizbi.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 0f be 11 90 03 05 08 83 f2 90 01 01 81 f2 90 01 01 00 00 00 88 55 ef 8b 45 f4 83 c0 01 89 45 f4 8b 4d f0 8a 55 ef 88 11 8b 45 f0 83 c0 01 89 45 f0 8b 4d e8 83 c1 01 89 4d e8 0f be 55 ef 85 d2 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}