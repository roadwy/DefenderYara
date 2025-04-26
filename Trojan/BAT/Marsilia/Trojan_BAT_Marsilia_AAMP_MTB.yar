
rule Trojan_BAT_Marsilia_AAMP_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AAMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 3c 08 00 70 28 ?? ?? 00 06 1c 2d 1c 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 01 00 06 1b 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de cd } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}