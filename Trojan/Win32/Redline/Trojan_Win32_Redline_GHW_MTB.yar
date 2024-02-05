
rule Trojan_Win32_Redline_GHW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 1d 90 01 04 0f b6 07 03 c8 0f b6 c1 8a 84 05 90 01 04 32 86 90 01 04 88 86 90 01 04 c7 45 90 01 05 8b 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}