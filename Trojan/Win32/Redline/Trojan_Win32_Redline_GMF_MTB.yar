
rule Trojan_Win32_Redline_GMF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f7 d9 88 8d 90 01 04 0f b6 95 90 01 04 03 95 90 01 04 88 95 90 01 04 0f b6 85 90 01 04 f7 d0 88 85 90 01 04 0f b6 8d 90 01 04 83 f1 38 88 8d 90 01 04 8b 95 90 01 04 8a 85 90 01 04 88 84 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}