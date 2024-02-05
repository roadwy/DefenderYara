
rule Trojan_Win32_Tofsee_PVS_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 f8 81 e7 ff 00 00 00 81 3d 90 01 04 81 0c 00 00 75 90 09 0c 00 a1 90 01 04 0f b6 b8 90 00 } //01 00 
		$a_02_1 = {30 04 1f 4f 79 90 09 05 00 e8 90 00 } //02 00 
		$a_02_2 = {05 c3 9e 26 00 a3 90 01 04 ff 15 90 01 04 a0 90 01 04 30 04 1e 46 3b f7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}