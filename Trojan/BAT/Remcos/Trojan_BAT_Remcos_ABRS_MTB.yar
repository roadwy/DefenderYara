
rule Trojan_BAT_Remcos_ABRS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0d 04 03 6f ?? 00 00 0a 59 13 04 72 ?? 06 00 70 0e 05 8c ?? 00 00 01 28 ?? 00 00 0a 13 05 11 05 72 ?? 06 00 70 6f ?? 00 00 0a 2c 05 08 1f 63 58 0c 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 17 59 25 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}