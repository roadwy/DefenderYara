
rule Trojan_Win32_Redline_GBF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {99 33 c1 8b 8d 90 01 04 33 d6 8b b5 90 01 04 23 c1 23 d6 89 85 90 01 04 89 95 90 01 04 4f 75 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}