
rule Trojan_Win32_Vidar_GFE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b c1 99 8b 4d d0 8b 75 d4 33 c8 33 f2 88 0d 90 01 04 0f b7 85 6c ff ff ff 99 8b 4d 90 01 01 8b 75 94 23 c8 23 f2 88 4d e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}