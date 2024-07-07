
rule Trojan_BAT_Stealer_ML_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 07 08 09 28 90 01 0e 28 90 01 04 13 04 11 04 72 90 01 04 6f 90 01 04 13 05 11 05 72 90 01 04 6f 90 01 04 13 06 73 90 01 04 13 07 11 06 6f 90 01 04 14 17 8d 90 01 04 25 16 11 07 6f 90 01 04 a2 6f 90 01 04 26 20 90 01 04 13 08 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}