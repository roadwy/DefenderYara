
rule Trojan_BAT_Crysan_NYS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.NYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 28 00 00 0a 0a 73 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 13 06 11 06 08 6f ?? 00 00 0a 11 06 18 6f ?? 00 00 0a 11 06 18 6f ?? 00 00 0a 11 06 0d 09 6f ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 07 de 14 } //5
		$a_01_1 = {63 64 72 6b 53 49 2e 72 65 73 6f 75 72 63 65 73 } //1 cdrkSI.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}