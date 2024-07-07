
rule Trojan_Win32_EmotetCrypt_PCT_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8a 0c 38 02 4d 0f 8b 45 f4 8b 55 e4 32 0c 02 88 08 40 ff 4d f0 89 45 f4 0f 85 } //1
		$a_03_1 = {0f b6 14 29 0f b6 04 2e 03 c2 99 bb 90 01 04 f7 fb 0f b6 c2 8a 14 28 8b 44 24 90 01 01 30 14 07 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}