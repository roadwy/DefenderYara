
rule Trojan_Win32_TrickBotCrypt_GJ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 0f b6 55 90 01 01 33 ca 8b 45 90 01 01 2b 45 90 01 01 0f b6 d0 81 e2 e0 00 00 00 33 ca 8b 45 90 01 01 88 08 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}