
rule Trojan_Win32_Redline_UT_MTB{
	meta:
		description = "Trojan:Win32/Redline.UT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {57 8b fa 39 75 90 01 01 76 13 33 d2 8b c6 f7 75 90 01 01 8a 04 0a 30 04 3e 46 3b 75 90 01 01 72 ed 8b c7 5f 5e 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}