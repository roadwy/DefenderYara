
rule Trojan_Win32_Redline_UT_MTB{
	meta:
		description = "Trojan:Win32/Redline.UT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8b fa 39 75 ?? 76 13 33 d2 8b c6 f7 75 ?? 8a 04 0a 30 04 3e 46 3b 75 ?? 72 ed 8b c7 5f 5e 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}