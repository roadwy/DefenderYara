
rule Trojan_Win32_PikaBot_CCFK_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 90 01 01 0f af 45 90 01 01 2b d0 03 55 90 01 01 03 55 90 01 01 2b 55 90 01 01 0f b6 54 15 90 01 01 33 ca 8b 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}