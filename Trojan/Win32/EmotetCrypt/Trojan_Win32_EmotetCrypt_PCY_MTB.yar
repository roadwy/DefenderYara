
rule Trojan_Win32_EmotetCrypt_PCY_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 24 90 01 01 8b 15 90 01 04 8a 0c 11 8b 44 24 90 01 01 30 0c 28 45 3b 6c 24 90 01 01 0f 8c 90 01 04 8b 44 24 90 01 01 8a 54 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}