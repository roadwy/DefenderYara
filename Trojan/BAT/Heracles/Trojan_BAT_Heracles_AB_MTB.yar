
rule Trojan_BAT_Heracles_AB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 fe 0c 02 00 93 fe 0e 03 00 fe 0c 00 00 fe 0c 03 00 fe 09 02 00 59 d1 6f 07 00 00 0a 26 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 01 00 8e 69 32 c5 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}