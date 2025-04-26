
rule Trojan_BAT_LummaC_SWD_MTB{
	meta:
		description = "Trojan:BAT/LummaC.SWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 87 00 00 06 1f 24 8d 1e 00 00 01 25 d0 07 00 00 04 28 17 00 00 0a 80 03 00 00 04 20 4b 05 00 00 8d 1e 00 00 01 25 d0 08 00 00 04 28 17 00 00 0a 80 04 00 00 04 14 80 05 00 00 04 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}