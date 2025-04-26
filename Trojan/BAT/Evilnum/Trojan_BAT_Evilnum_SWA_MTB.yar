
rule Trojan_BAT_Evilnum_SWA_MTB{
	meta:
		description = "Trojan:BAT/Evilnum.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 09 08 6f 14 00 00 0a 6f ?? 00 00 0a 26 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 00 09 16 09 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 17 13 05 2b d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}