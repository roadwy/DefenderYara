
rule Trojan_Win32_TrickBotCrypt_EX_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 0f b6 85 90 01 04 33 d0 8b 8d 90 01 04 2b 8d 90 01 04 0f b6 c1 25 ff 90 01 03 33 d0 8b 8d 90 01 04 88 11 0f b7 95 90 01 04 52 8b 45 f8 50 ff 15 90 01 04 8b 8d 90 01 04 03 4d f0 89 8d 90 01 04 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}