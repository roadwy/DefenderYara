
rule Trojan_Win32_EmotetCrypt_PCY_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 24 ?? 8b 15 ?? ?? ?? ?? 8a 0c 11 8b 44 24 ?? 30 0c 28 45 3b 6c 24 ?? 0f 8c ?? ?? ?? ?? 8b 44 24 ?? 8a 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}