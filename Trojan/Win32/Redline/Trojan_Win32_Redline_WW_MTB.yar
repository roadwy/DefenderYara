
rule Trojan_Win32_Redline_WW_MTB{
	meta:
		description = "Trojan:Win32/Redline.WW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 89 c8 3a 43 00 88 8d 90 01 04 0f b6 85 90 01 04 8b 0d 90 01 04 03 8d 90 01 04 0f be 11 33 d0 a1 90 01 04 03 85 90 01 04 88 10 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}