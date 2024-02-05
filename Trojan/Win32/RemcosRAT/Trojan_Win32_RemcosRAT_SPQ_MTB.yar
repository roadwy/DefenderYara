
rule Trojan_Win32_RemcosRAT_SPQ_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 0f b6 8c 0d e8 fe ff ff 03 4d f8 8b 45 fc 33 d2 f7 75 0c 8b 45 08 0f b6 14 10 03 ca 8b c1 33 d2 f7 75 f0 89 55 f8 8b 45 fc 8a 8c 05 e8 fe ff ff 88 4d f7 8b 55 fc 8b 45 f8 8a 8c 05 e8 fe ff ff 88 8c 15 e8 fe ff ff 8b 55 f8 8a 45 f7 88 84 15 e8 fe ff ff 33 c9 75 ce } //00 00 
	condition:
		any of ($a_*)
 
}