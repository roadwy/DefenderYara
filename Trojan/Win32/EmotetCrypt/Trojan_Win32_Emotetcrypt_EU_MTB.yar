
rule Trojan_Win32_Emotetcrypt_EU_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 30 0f b6 14 0a 89 44 24 18 8b c6 2b 44 24 10 bb ?? ?? ?? ?? 0f b6 04 38 03 c2 33 d2 f7 f3 8b 44 24 18 2b 54 24 34 03 d5 8a 14 3a 30 10 } //1
		$a_03_1 = {0f b6 14 2a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 6c 24 44 8b c7 2b c1 2b c6 03 54 24 40 8d 04 82 8b 54 24 4c 03 c3 8a 04 10 30 45 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}