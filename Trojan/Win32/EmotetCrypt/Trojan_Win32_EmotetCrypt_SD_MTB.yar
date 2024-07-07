
rule Trojan_Win32_EmotetCrypt_SD_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b f0 6a 90 01 01 8b ce e8 90 01 04 8b ce e8 90 01 04 0f b6 54 24 11 a1 90 01 04 8a 0c 02 8b 44 24 20 30 0c 28 45 3b 6c 24 24 0f 8c 90 01 02 ff ff 8b 44 24 28 8a 54 24 12 8a 4c 24 13 5f 5e 5b 88 10 88 48 01 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}