
rule Trojan_BAT_Rozena_FJAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.FJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 8e 69 0c 7e ?? 00 00 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? 00 00 06 0d 16 09 08 28 ?? 00 00 0a 7e ?? 00 00 0a 16 09 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}