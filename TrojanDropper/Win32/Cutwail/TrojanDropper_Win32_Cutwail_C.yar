
rule TrojanDropper_Win32_Cutwail_C{
	meta:
		description = "TrojanDropper:Win32/Cutwail.C,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 3d 68 a0 12 00 01 50 e8 e7 fe ff ff 6a 01 8d 85 f4 fd ff ff 50 6a 65 53 e8 78 fd ff ff 56 8d 85 dc fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}