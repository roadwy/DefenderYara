
rule Trojan_Win32_Tofsee_DSK_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 a3 90 01 04 81 05 90 01 04 c3 9e 26 00 0f b7 05 90 00 } //01 00 
		$a_02_1 = {30 01 46 3b 74 24 0c 7c 90 09 05 00 e8 90 00 } //02 00 
		$a_02_2 = {8b 55 c4 8b c7 c1 e8 05 03 45 b0 03 cb 03 d7 33 ca 81 3d 90 01 04 72 07 00 00 90 00 } //02 00 
		$a_02_3 = {8b 54 24 10 8b c7 c1 e8 05 03 44 24 38 03 d7 33 ca 81 3d 90 01 04 72 07 00 00 90 00 } //02 00 
		$a_00_4 = {8a 3a 89 f1 0f b6 30 30 df 29 ce 88 38 } //00 00 
	condition:
		any of ($a_*)
 
}