
rule Trojan_BAT_Donut_SLG_MTB{
	meta:
		description = "Trojan:BAT/Donut.SLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 02 8e 69 7e 05 00 00 04 7e 08 00 00 04 6f ?? 00 00 06 13 0c 72 ?? 05 1a 70 13 04 00 11 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}