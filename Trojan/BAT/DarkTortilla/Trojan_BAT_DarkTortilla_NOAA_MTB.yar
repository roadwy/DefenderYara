
rule Trojan_BAT_DarkTortilla_NOAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.NOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 6f ?? 01 00 0a 13 06 73 ?? 01 00 0a 0d 09 11 06 17 73 ?? 01 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 01 00 0a 11 04 6f ?? 01 00 0a 09 6f ?? 01 00 0a 0c de 23 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}