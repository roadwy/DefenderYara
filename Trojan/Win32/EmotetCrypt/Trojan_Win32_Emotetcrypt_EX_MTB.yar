
rule Trojan_Win32_Emotetcrypt_EX_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 10 8b 54 24 ?? 8a 14 3a 88 14 2e 8b 54 24 ?? 88 04 3a 8b 44 24 ?? 0f b6 04 30 8b 54 24 ?? 0f b6 14 17 03 c2 33 d2 5d f7 f5 8b 44 24 ?? 8b 6c 24 ?? 03 54 24 ?? 8a 04 02 30 04 2b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}