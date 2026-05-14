
rule Trojan_Win32_Mikey_LMK_MTB{
	meta:
		description = "Trojan:Win32/Mikey.LMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 c6 44 24 1c 43 88 44 24 1e 88 4c 24 1f c6 44 24 20 74 88 44 24 21 c6 44 24 22 54 c6 44 24 23 68 88 44 24 25 88 4c 24 26 c6 44 24 27 64 c6 44 24 28 00 } //20
		$a_03_1 = {8b b4 24 88 06 00 00 8b c6 57 8d 50 02 66 8b 08 83 c0 02 66 85 c9 75 ?? 2b c2 d1 f8 8d 0c 46 89 4c 24 54 8b c1 3b ce } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}