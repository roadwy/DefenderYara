
rule Trojan_BAT_AstasiaLoader_PA_MTB{
	meta:
		description = "Trojan:BAT/AstasiaLoader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  \infected.exe
		$a_01_1 = {41 00 73 00 74 00 61 00 73 00 69 00 61 00 4c 00 6f 00 61 00 64 00 65 00 72 00 } //03 00  AstasiaLoader
		$a_03_2 = {07 1f 1c 28 90 01 01 00 00 0a 72 90 01 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 20 d0 07 00 00 28 90 01 01 00 00 0a 1f 1c 28 90 01 01 00 00 0a 72 90 01 04 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}