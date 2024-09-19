
rule Trojan_BAT_Jalapeno_VEAA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.VEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1b 12 05 2b 1b 08 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 1d 11 04 2b e1 28 ?? 00 00 0a 2b de 1e 2c 0b 11 05 2c 07 11 04 28 ?? 00 00 0a 1c 2c f6 dc 17 2c bd 09 18 25 2c 09 58 0d 09 07 6f ?? 00 00 0a 3f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}