
rule Trojan_BAT_Zusy_SWB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d de 0a 08 2c 06 08 6f ?? 00 00 0a dc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}