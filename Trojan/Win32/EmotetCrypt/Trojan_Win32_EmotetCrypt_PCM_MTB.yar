
rule Trojan_Win32_EmotetCrypt_PCM_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 10 88 18 8b 5d f8 88 14 33 0f b6 00 0f b6 d2 03 c2 33 d2 f7 f1 8b 4d f0 8a 04 32 32 04 39 88 07 } //1
		$a_03_1 = {0f b6 0c 0a 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 55 e4 8b 45 08 03 45 dc 0f b6 00 8b 4d f0 03 4d e4 0f b6 09 33 c1 8b 4d 18 03 4d dc 88 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}