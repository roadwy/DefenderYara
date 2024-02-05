
rule VirTool_BAT_Banfus_A{
	meta:
		description = "VirTool:BAT/Banfus.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {1d 00 00 11 00 02 28 90 01 01 00 00 0a 00 02 02 8e b7 17 da 91 0d 28 90 01 01 00 00 0a 03 6f 90 01 01 00 00 0a 13 04 02 8e b7 17 d6 8d 59 00 00 01 0c 16 0a 16 02 90 00 } //01 00 
		$a_01_1 = {63 64 70 61 70 78 61 6c 5a 5a 5a 73 73 73 41 41 41 76 62 63 63 64 70 61 70 78 61 6c 5a 5a 5a 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}