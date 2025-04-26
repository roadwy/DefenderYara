
rule Trojan_BAT_Amadey_PTDI_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PTDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e b1 00 00 04 7e b0 00 00 04 28 ?? 01 00 06 14 fe 06 5f 00 00 06 73 30 00 00 0a 28 ?? 01 00 06 17 80 63 00 00 04 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}