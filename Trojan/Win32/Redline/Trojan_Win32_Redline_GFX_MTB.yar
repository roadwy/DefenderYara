
rule Trojan_Win32_Redline_GFX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b7 45 dc 99 8b 4d a8 8b 75 ac 33 c8 33 f2 89 8d 90 01 04 89 b5 90 01 04 8b 95 90 01 04 0b 95 90 01 04 75 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}