
rule Worm_Win32_Autorun_WA{
	meta:
		description = "Worm:Win32/Autorun.WA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 02 74 1a 56 e8 90 01 02 ff ff 83 f8 04 74 0f 56 e8 90 01 02 ff ff 83 f8 03 0f 85 90 01 02 00 00 90 00 } //01 00 
		$a_03_1 = {43 80 fb 7b 0f 85 90 01 01 ff ff ff 6a 04 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}