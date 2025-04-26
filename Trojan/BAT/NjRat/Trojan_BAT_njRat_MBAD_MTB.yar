
rule Trojan_BAT_njRat_MBAD_MTB{
	meta:
		description = "Trojan:BAT/njRat.MBAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 04 09 04 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 13 04 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 09 17 d6 0d 09 08 31 cb } //10
		$a_01_1 = {56 65 67 69 6e 65 72 65 44 65 63 72 79 70 74 } //2 VeginereDecrypt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}