
rule TrojanDropper_Win32_Cutwail_G{
	meta:
		description = "TrojanDropper:Win32/Cutwail.G,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 18 72 40 00 8d 4c 24 0c 51 8d 94 24 18 02 00 00 68 08 72 40 00 52 e8 7c 01 00 00 } //01 00 
		$a_01_1 = {68 50 62 14 13 8d 4c 24 10 51 8d 94 24 18 01 00 00 68 40 62 14 13 52 e8 d5 02 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}