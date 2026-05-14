
rule Trojan_BAT_Remcos_ABRM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 31 11 32 6f ?? 00 00 0a 13 33 11 1e 03 fe 04 13 34 11 34 2c 17 00 11 1b 12 33 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 1e 17 58 13 1e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}