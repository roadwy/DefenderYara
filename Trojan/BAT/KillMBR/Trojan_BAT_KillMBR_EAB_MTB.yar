
rule Trojan_BAT_KillMBR_EAB_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.EAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 09 11 05 11 05 1f 0a 11 05 1f 17 62 11 05 1c 63 60 11 05 20 80 00 00 00 61 60 11 05 1b 62 11 05 1d 63 60 5f 5a 5a d2 9c 00 11 05 17 58 13 05 11 05 09 8e 69 fe 04 13 06 11 06 2d c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}