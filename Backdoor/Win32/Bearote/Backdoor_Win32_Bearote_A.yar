
rule Backdoor_Win32_Bearote_A{
	meta:
		description = "Backdoor:Win32/Bearote.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {76 1d 6a 05 53 e8 90 01 02 ff ff 8b f8 89 fe 85 ff 74 0d 6a ff 8d 85 90 01 02 ff ff 50 6a 00 ff d6 90 00 } //01 00 
		$a_03_1 = {85 c0 74 11 68 90 01 04 6a 00 6a 00 50 e8 90 01 04 8b d8 85 db 74 0f 6a 00 6a 00 68 f5 00 00 00 53 e8 90 00 } //01 00 
		$a_03_2 = {83 fe 05 75 22 90 01 22 83 fe 06 75 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}