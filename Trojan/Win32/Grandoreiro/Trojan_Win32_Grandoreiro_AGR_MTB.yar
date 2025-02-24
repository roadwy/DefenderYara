
rule Trojan_Win32_Grandoreiro_AGR_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.AGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 eb c1 fa 02 8b c2 c1 e8 1f 03 d0 03 d2 8d 14 92 8b c3 2b c2 04 30 0f b6 d1 88 82 19 ?? b9 02 b8 67 66 66 66 f7 eb c1 fa 02 8b da c1 eb 1f 03 da 49 85 db } //3
		$a_03_1 = {ba 0f 00 00 00 23 d0 0f b6 92 37 ?? b9 02 0f b6 d9 88 93 19 ?? b9 02 c1 e8 04 49 85 c0 75 e1 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}