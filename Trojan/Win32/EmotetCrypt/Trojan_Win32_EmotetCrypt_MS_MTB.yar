
rule Trojan_Win32_EmotetCrypt_MS_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 03 45 f8 89 45 e4 8b 4d f4 03 4d e8 89 4d f0 c7 05 [0-08] c7 05 [0-08] 8b 55 f4 c1 ea 05 89 55 ec 8b 45 ec 03 45 d4 89 45 ec 8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 45 d8 29 45 e8 } //1
		$a_02_1 = {8b 4d e4 03 d9 8b 4d f8 8b c6 c1 e8 05 03 45 e8 03 ce 33 d9 33 d8 c7 05 [0-08] c7 05 [0-08] 89 45 fc 2b fb 8b 45 e0 29 45 f8 83 6d f4 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}