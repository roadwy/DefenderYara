
rule Trojan_BAT_Heracles_PSRV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSRV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 09 16 09 8e 69 6f 1d 00 00 0a 0d 02 90 0a 37 00 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}