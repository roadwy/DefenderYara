
rule Trojan_Win32_PikaBot_CCFJ_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 01 8b 85 90 01 01 fe ff ff 33 d2 be 90 01 04 f7 f6 0f b6 54 15 90 01 01 33 ca 8b 85 90 01 01 fe ff ff 2b 85 90 01 01 ff ff ff 03 85 90 01 01 ff ff ff 8b 95 90 01 01 ff ff ff 88 0c 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}