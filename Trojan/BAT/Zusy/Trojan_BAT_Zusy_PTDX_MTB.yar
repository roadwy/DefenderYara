
rule Trojan_BAT_Zusy_PTDX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 75 00 00 0a 0c 00 03 28 90 01 01 00 00 0a 73 77 00 00 0a 13 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}