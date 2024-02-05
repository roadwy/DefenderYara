
rule Trojan_Win32_TrickInj_B_MTB{
	meta:
		description = "Trojan:Win32/TrickInj.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {5b 49 4e 49 54 5d 20 42 43 20 3d 20 25 75 } //01 00 
		$a_81_1 = {23 70 67 69 64 23 } //01 00 
		$a_81_2 = {69 6e 6a 5f 33 32 2e 64 6c 6c } //01 00 
		$a_81_3 = {23 67 69 64 23 } //01 00 
		$a_03_4 = {23 69 64 23 90 02 2f 51 43 6f 6e 6e 65 63 74 69 6f 6e 90 00 } //01 00 
		$a_81_5 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00 
		$a_01_6 = {84 c0 75 ec 81 f6 34 70 00 10 81 fe 5f b8 ec 0e 74 25 81 fe 7b f8 87 0f 74 19 81 fe a5 50 5a c3 74 0d 33 c0 81 fe 8f 22 34 ea 0f 94 c0 } //00 00 
	condition:
		any of ($a_*)
 
}