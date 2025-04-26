
rule Trojan_Win32_EmotetCrypt_PCL_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 10 [0-14] 8b 44 24 24 8b 4c 24 18 0f b6 14 01 8b 4c 24 10 32 14 31 83 c0 01 83 6c 24 14 01 88 50 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}