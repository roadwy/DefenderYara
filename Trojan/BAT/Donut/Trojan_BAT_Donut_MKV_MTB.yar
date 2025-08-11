
rule Trojan_BAT_Donut_MKV_MTB{
	meta:
		description = "Trojan:BAT/Donut.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 06 08 20 e8 03 00 00 73 3f 00 00 0a 13 05 00 11 05 1f 20 6f ?? 00 00 0a 13 06 73 41 00 00 0a 13 07 00 11 07 20 00 01 00 00 6f ?? 00 00 0a 00 11 07 17 6f ?? 00 00 0a 00 11 07 18 6f ?? 00 00 0a 00 11 07 11 06 09 6f ?? 00 00 0a 13 08 00 11 04 73 52 00 00 0a 13 09 00 11 09 11 08 16 73 47 00 00 0a 13 0a 11 0a 28 ?? 00 00 0a 73 53 00 00 0a 13 0b 00 11 0b 6f ?? 00 00 0a 13 0c de 4e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}