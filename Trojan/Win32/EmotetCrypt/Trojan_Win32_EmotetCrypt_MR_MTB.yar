
rule Trojan_Win32_EmotetCrypt_MR_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 02 8b 44 24 ?? 8a 14 03 32 d1 88 14 03 8b 44 24 ?? 43 3b d8 0f 8c 90 09 0f 00 8b 54 24 ?? a1 ?? ?? ?? ?? 81 e2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}