
rule Trojan_Win32_Redline_GJL_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {88 55 cb 0f b6 45 cb 50 8d 4d e0 e8 90 01 04 0f b6 08 8b 55 08 03 55 cc 0f b6 02 33 c1 8b 4d 08 03 4d cc 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}