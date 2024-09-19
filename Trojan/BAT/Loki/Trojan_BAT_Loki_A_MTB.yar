
rule Trojan_BAT_Loki_A_MTB{
	meta:
		description = "Trojan:BAT/Loki.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 13 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}