
rule Trojan_Win32_EmotetCrypt_PCR_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 30 f7 35 ?? ?? ?? ?? 8b da 03 d9 ff 15 ?? ?? ?? ?? 8a 14 33 8a 44 24 28 8b 4c 24 1c 02 d0 8b 44 24 24 32 14 01 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}