
rule Trojan_BAT_DcRat_ZNR_MTB{
	meta:
		description = "Trojan:BAT/DcRat.ZNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 06 11 05 6f ?? 00 00 0a 13 07 09 11 04 20 ff 00 00 00 12 07 28 ?? 00 00 0a 59 1f 72 61 d2 9c 11 06 17 58 13 06 11 04 17 58 13 04 11 06 07 2f 07 11 04 09 8e 69 32 c7 11 05 17 58 13 05 11 05 08 32 b7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}