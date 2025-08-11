
rule Trojan_BAT_NetSupportRat_ANR_MTB{
	meta:
		description = "Trojan:BAT/NetSupportRat.ANR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 33 02 de 46 06 28 ?? 00 00 0a 26 06 28 ?? 00 00 06 26 72 ?? 00 00 70 28 ?? 00 00 06 0d 09 2c 04 09 8e ?? 02 de 24 09 06 28 ?? 00 00 06 06 28 } //2
		$a_01_1 = {31 00 38 00 35 00 2e 00 31 00 34 00 39 00 2e 00 31 00 34 00 36 00 2e 00 37 00 33 00 } //5 185.149.146.73
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*5) >=7
 
}