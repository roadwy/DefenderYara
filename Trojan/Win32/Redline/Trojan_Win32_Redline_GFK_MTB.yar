
rule Trojan_Win32_Redline_GFK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 98 90 01 04 32 1c 37 ba 90 01 04 e8 90 01 04 50 e8 90 01 04 59 0f b6 04 37 8d 0c 03 88 0c 37 2a c8 88 0c 37 46 8b 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}