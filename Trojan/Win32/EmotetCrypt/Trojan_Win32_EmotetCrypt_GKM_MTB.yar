
rule Trojan_Win32_EmotetCrypt_GKM_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 bd 5f 02 00 00 f7 fd a1 90 01 04 0f b6 ea 03 c5 88 54 24 90 01 01 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 90 01 01 8b 35 90 01 04 8b 44 24 90 01 01 8a 14 32 8b 90 02 03 30 14 08 40 3b 90 02 03 89 44 24 90 01 01 0f 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}