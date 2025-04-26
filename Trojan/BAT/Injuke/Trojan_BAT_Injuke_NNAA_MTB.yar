
rule Trojan_BAT_Injuke_NNAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0c 11 02 6f ?? 00 00 0a 20 00 00 00 00 28 ?? 00 00 06 3a ?? ff ff ff 26 38 ?? ff ff ff 00 00 11 0c 28 ?? 00 00 06 13 09 } //2
		$a_03_1 = {11 09 11 03 16 11 03 8e 69 6f ?? 00 00 0a 13 07 38 00 00 00 00 11 07 13 0b } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}