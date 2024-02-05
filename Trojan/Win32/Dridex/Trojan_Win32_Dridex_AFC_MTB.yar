
rule Trojan_Win32_Dridex_AFC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 08 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {9e d9 30 dd 1f 7c 7e 9a a6 b0 5f 36 74 03 40 c8 90 80 8e 5e f7 42 2c 56 fa 74 b1 fd 97 38 6c 3c 6b d9 31 dd d3 af fe 9b a6 10 92 36 88 03 a0 c8 11 34 c2 3f e3 42 0c 56 19 55 32 b1 97 38 6c bb } //03 00 
		$a_80_1 = {2d 2d 73 2d 2d 70 70 2d 2d 2d 2d } //--s--pp----  03 00 
		$a_80_2 = {47 73 70 2e 70 64 62 } //Gsp.pdb  01 00 
		$a_81_3 = {23 3a 23 5c 23 45 23 54 23 50 23 2e 23 58 23 } //01 00 
		$a_81_4 = {23 50 23 45 23 45 23 54 23 50 23 2e 23 58 23 } //00 00 
	condition:
		any of ($a_*)
 
}