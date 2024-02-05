
rule Trojan_Win32_Redline_RPO_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {99 b9 17 00 00 00 f7 f9 6b c0 26 6b c0 38 99 b9 0b 00 00 00 f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}