
rule Trojan_Win32_TrickBotCrypt_GR_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d e4 3b 4d f4 73 90 01 01 8b 55 e4 0f b6 02 0f b6 4d eb 33 c1 8b 55 e4 2b 55 08 0f b6 ca 81 e1 ff 00 00 00 33 c1 8b 55 e4 88 02 8b 45 e4 03 45 f8 89 45 e4 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}