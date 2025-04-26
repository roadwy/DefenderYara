
rule Trojan_BAT_Injuke_ABVL_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 11 2b 16 74 ?? 00 00 01 2b 16 74 ?? 00 00 1b 2b 16 2a 28 ?? ?? 00 06 2b e8 28 ?? ?? 00 06 2b e3 28 ?? ?? 00 06 2b e3 28 ?? ?? 00 06 2b e3 } //2
		$a_03_1 = {2b 05 2b 06 2b 0b 2a 02 2b f8 28 ?? 00 00 2b 2b f3 28 ?? 00 00 2b 2b ee } //2
		$a_01_2 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}