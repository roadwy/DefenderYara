
rule Trojan_Win32_TrickBotCrypt_DF_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 55 fc 33 d2 f7 35 90 01 04 8b 45 0c 8a 1d 90 01 04 89 55 f4 8b 55 f8 8d 0c 02 8a c3 f6 eb 8b 5d f4 8a 1c 33 2a d8 30 19 42 89 55 f8 3b 55 10 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}