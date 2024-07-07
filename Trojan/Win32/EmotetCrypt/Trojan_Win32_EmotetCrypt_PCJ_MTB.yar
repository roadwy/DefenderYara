
rule Trojan_Win32_EmotetCrypt_PCJ_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 2c 83 f0 ff 89 44 24 2c 8b 44 24 24 8a 3c 30 28 df 8b 54 24 20 88 3c 32 83 c6 25 8b 7c 24 28 39 fe 89 74 24 14 0f 82 } //1
		$a_01_1 = {8b 44 24 4c 8b 4c 24 34 8a 54 24 4b 8a 30 28 d6 8b 44 24 24 88 34 08 8b 4c 24 34 83 c1 33 89 4c 24 50 8b 74 24 2c 39 f1 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}