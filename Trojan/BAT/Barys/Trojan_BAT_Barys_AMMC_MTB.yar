
rule Trojan_BAT_Barys_AMMC_MTB{
	meta:
		description = "Trojan:BAT/Barys.AMMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 11 b0 18 6f ?? 00 00 0a 11 b0 17 6f ?? 00 00 0a 11 b0 6f ?? 00 00 0a 02 16 02 8e b7 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}