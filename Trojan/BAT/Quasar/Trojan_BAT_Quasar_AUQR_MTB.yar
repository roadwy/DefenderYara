
rule Trojan_BAT_Quasar_AUQR_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AUQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 28 ?? 02 00 0a 28 ?? 02 00 0a 0c 06 28 ?? 02 00 0a 3a 1a 00 00 00 06 28 ?? 03 00 0a 26 06 73 ?? 03 00 0a 25 6f ?? 04 00 0a 18 60 6f ?? 04 00 0a 08 28 ?? 02 00 0a 3a 0e 00 00 00 07 08 28 ?? 03 00 0a 08 18 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}