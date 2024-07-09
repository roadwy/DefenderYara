
rule Trojan_Win32_Bamital_G{
	meta:
		description = "Trojan:Win32/Bamital.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 7d 0c 01 75 17 60 68 ?? ?? ?? ?? e8 (75|7d) ff ff ff 0b c0 74 07 8b c8 8b 45 08 ff d1 61 } //1
		$a_03_1 = {83 7d 0c 01 75 1b 60 8d 15 ?? ?? ?? ?? 52 e8 90 17 05 01 01 01 01 01 3c 4b 61 62 6e ff ff ff 8b c8 0b c9 74 07 8b d0 8b 45 08 ff d2 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}