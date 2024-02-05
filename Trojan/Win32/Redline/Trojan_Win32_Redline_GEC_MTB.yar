
rule Trojan_Win32_Redline_GEC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 c8 29 d0 89 c2 8b 45 90 01 01 01 d0 0f b6 00 83 e0 90 01 01 31 d8 88 45 90 01 01 0f b6 45 90 01 01 8d 0c 00 8b 55 90 01 01 8b 45 90 01 01 01 d0 89 ca 88 10 8b 55 90 01 01 8b 45 90 01 01 01 d0 0f b6 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}