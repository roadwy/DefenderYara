
rule Trojan_BAT_Remcos_ABYR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 87 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 02 00 06 16 39 ?? 00 00 00 26 38 00 00 00 00 dd ?? ff ff ff 13 00 38 00 00 00 00 38 ?? ff ff ff 26 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}