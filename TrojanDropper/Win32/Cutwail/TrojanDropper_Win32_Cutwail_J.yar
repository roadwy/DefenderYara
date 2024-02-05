
rule TrojanDropper_Win32_Cutwail_J{
	meta:
		description = "TrojanDropper:Win32/Cutwail.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {9c 71 9c 40 01 81 83 10 34 50 b0 81 3d 00 04 0c e5 50 c0 c1 04 12 28 58 c4 a1 40 01 06 10 28 60 } //00 00 
	condition:
		any of ($a_*)
 
}