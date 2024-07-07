
rule Trojan_Win32_Stealc_GJT_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 33 c6 d1 e8 33 c6 c1 e8 90 01 01 33 c6 83 e0 90 01 01 a3 90 01 04 c1 e0 90 01 01 66 d1 e9 66 0b c8 0f b7 f1 33 d2 6a 90 01 01 5b 8b c6 f7 f3 8b 45 90 01 01 8b 1f 8a 14 02 8b 45 90 01 01 88 14 18 40 89 45 90 01 01 3b 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}