
rule Trojan_Win32_EmotetCrypt_PCW_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 29 0f b6 0c 0f 03 c1 99 b9 ?? ?? ?? ?? f7 f9 88 54 24 11 [0-0c] 0f b6 54 24 11 a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 ?? 30 0c 03 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}