
rule TrojanDropper_Win32_Koobface_M{
	meta:
		description = "TrojanDropper:Win32/Koobface.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b3 01 6a 02 56 e8 90 01 04 56 e8 90 01 04 e8 90 01 04 8a c3 90 00 } //01 00 
		$a_01_1 = {68 95 1f 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}