
rule Backdoor_Win32_Escad_D_dha{
	meta:
		description = "Backdoor:Win32/Escad.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {1f f7 d1 18 e8 } //01 00 
		$a_01_1 = {97 f1 6f c4 75 } //02 00 
		$a_01_2 = {5f 65 78 65 00 00 00 00 5f 70 75 74 00 00 00 00 5f 71 75 69 74 00 00 00 5f 67 6f 74 00 00 00 00 5f 67 65 74 00 00 00 00 5f 64 65 6c 00 00 00 00 5f 64 69 72 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}