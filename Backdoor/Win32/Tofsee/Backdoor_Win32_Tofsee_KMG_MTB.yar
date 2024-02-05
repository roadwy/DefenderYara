
rule Backdoor_Win32_Tofsee_KMG_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 fb 85 02 00 00 75 90 01 01 ff b5 90 01 04 57 57 ff 15 90 01 04 e8 90 01 04 8b 8d 90 01 04 30 04 31 81 fb 4a 02 00 00 75 90 00 } //01 00 
		$a_02_1 = {81 fb 85 02 00 00 75 90 01 01 ff b5 90 01 04 57 57 ff 15 90 01 04 e8 90 01 04 8b 8d 90 01 04 30 04 31 83 fb 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}