
rule Trojan_Win32_TrickBotCrypt_DS_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 0f b6 4d 90 01 01 33 c1 8b 55 90 01 01 2b 55 90 01 01 0f b6 ca 83 e1 20 33 c1 8b 55 90 01 01 88 02 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}