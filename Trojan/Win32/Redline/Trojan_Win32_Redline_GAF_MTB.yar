
rule Trojan_Win32_Redline_GAF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f7 d8 88 45 90 01 01 0f b6 4d 90 01 01 83 e9 90 01 01 88 4d 90 01 01 0f b6 55 90 01 01 f7 da 88 55 90 01 01 0f b6 45 90 01 01 d1 f8 0f b6 4d 90 01 01 c1 e1 90 01 01 0b c1 88 45 90 01 01 0f b6 55 90 01 01 2b 55 90 01 01 88 55 90 01 01 8b 45 90 01 01 8a 4d 90 01 01 88 4c 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}