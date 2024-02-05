
rule Trojan_Win32_Redline_GTT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 c1 e0 90 01 01 6b c0 90 01 01 b9 90 01 04 99 f7 f9 b9 90 01 04 99 f7 f9 6b f0 90 01 01 8b 45 0c 8b 4d f0 0f be 14 08 31 f2 88 14 08 8b 45 f0 83 c0 90 01 01 89 45 f0 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}