
rule Trojan_Win32_DarkKomet_MBHL_MTB{
	meta:
		description = "Trojan:Win32/DarkKomet.MBHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 97 4c 00 0b f0 30 01 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 01 00 e9 00 00 00 4c 93 4c 00 30 95 4c 00 28 15 40 00 78 } //1
		$a_01_1 = {48 da 41 00 0f f3 32 00 00 ff ff ff 08 00 00 00 01 00 00 00 04 00 04 00 e9 00 00 00 b8 d7 41 00 f4 e2 41 00 60 28 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}