
rule Trojan_BAT_Heracles_PTFV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 1a 01 00 00 fe 0e 2f 00 38 2d 35 00 00 3a 3f 12 00 00 fe 0c 2a 00 20 0b 00 00 00 fe 0c 2b 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}