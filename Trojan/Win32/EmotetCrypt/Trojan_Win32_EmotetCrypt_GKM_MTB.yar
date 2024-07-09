
rule Trojan_Win32_EmotetCrypt_GKM_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 bd 5f 02 00 00 f7 fd a1 ?? ?? ?? ?? 0f b6 ea 03 c5 88 54 24 ?? e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 ?? 8b 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 14 32 8b [0-03] 30 14 08 40 3b [0-03] 89 44 24 ?? 0f 8c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}