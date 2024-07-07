
rule Trojan_BAT_RedLine_RDEE_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}