
rule Trojan_Win32_Redline_GKY_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 04 02 6b c0 90 01 01 6b c0 90 01 01 99 b9 90 01 04 f7 f9 6b c0 90 01 01 99 b9 90 01 04 f7 f9 99 b9 90 01 04 f7 f9 6b c0 90 01 01 6b c0 90 01 01 99 b9 90 01 04 f7 f9 6b c0 90 01 01 6b c0 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f be 0a 33 c8 8b 55 90 01 01 03 55 90 01 01 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}