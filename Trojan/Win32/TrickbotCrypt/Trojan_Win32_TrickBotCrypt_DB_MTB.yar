
rule Trojan_Win32_TrickBotCrypt_DB_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 3b 81 e1 ff 00 00 00 03 c1 f7 35 90 01 04 89 54 24 90 00 } //1
		$a_03_1 = {ff d6 8b 54 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 8a 14 3a 30 14 08 8b 4c 24 90 01 01 40 3b c1 89 44 24 90 01 01 0f 82 66 ff ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}