
rule Trojan_Win64_Midie_AHC_MTB{
	meta:
		description = "Trojan:Win64/Midie.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 10 45 b0 f3 0f 7f 45 d8 8a 45 c0 88 45 e8 8a 45 c1 88 45 e9 48 8b 45 c8 48 89 45 f0 48 8d 05 ?? ?? ?? ?? 48 89 45 d0 eb 08 48 c7 45 d0 00 } //30
		$a_03_1 = {44 8b c0 b8 ?? ?? ?? ?? 41 f7 e8 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 1a 44 2b c1 41 8d 50 41 48 8d 4d c0 e8 } //20
		$a_80_2 = {4d 50 33 53 69 6d 57 6e 64 } //MP3SimWnd  5
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20+(#a_80_2  & 1)*5) >=55
 
}