
rule Trojan_Win32_RedLine_RDAS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 04 10 6b c0 38 99 b9 24 00 00 00 f7 f9 6b c0 16 6b c0 13 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}