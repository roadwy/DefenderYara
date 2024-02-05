
rule TrojanDropper_Win32_Cutwail_B{
	meta:
		description = "TrojanDropper:Win32/Cutwail.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff ff 6a 35 8d 90 01 02 fb ff ff 90 01 01 e8 90 01 02 00 00 83 c4 08 68 28 30 40 00 68 3f 00 0f 00 6a 00 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}