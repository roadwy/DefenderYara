
rule Trojan_Win32_Yedob_A_dha{
	meta:
		description = "Trojan:Win32/Yedob.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ad 3d 68 74 74 70 0f 85 90 01 02 00 00 ac 66 ad 66 3d 2f 2f 0f 85 90 01 02 00 00 89 f7 31 c9 80 3c 0f 3a 90 00 } //01 00 
		$a_03_1 = {58 c9 c3 56 57 be 90 01 03 00 89 f7 b9 90 01 02 00 00 8a 06 32 47 ff 32 47 fe 88 06 4e 4f 90 00 } //01 00 
		$a_01_2 = {61 63 63 65 70 74 65 64 2d } //00 00 
	condition:
		any of ($a_*)
 
}