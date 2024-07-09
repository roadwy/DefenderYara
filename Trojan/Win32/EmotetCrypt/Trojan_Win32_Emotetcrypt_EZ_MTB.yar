
rule Trojan_Win32_Emotetcrypt_EZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 08 8b 6c 24 ?? 8b f2 8b 54 24 ?? 8a 14 32 88 14 29 8b 54 24 ?? 88 04 32 8b 44 24 ?? 0f b6 04 30 8b 54 24 ?? 0f b6 14 0a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 44 24 ?? 8b 6c 24 ?? 03 54 24 ?? 03 d7 8a 04 02 30 04 2b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}