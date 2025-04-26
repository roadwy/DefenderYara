
rule Trojan_BAT_Rozena_SVJI_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SVJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 20 00 10 00 00 1a 28 ?? 00 00 06 0a 20 30 75 00 00 28 ?? 00 00 0a 02 16 06 02 8e 69 28 ?? 00 00 0a 20 30 75 00 00 28 ?? 00 00 0a 06 02 8e 69 20 00 10 00 00 1f 20 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}