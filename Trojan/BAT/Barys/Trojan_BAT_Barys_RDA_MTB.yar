
rule Trojan_BAT_Barys_RDA_MTB{
	meta:
		description = "Trojan:BAT/Barys.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 7e 00 00 0a 6f 80 00 00 0a 06 06 6f 81 00 00 0a 06 6f 82 00 00 0a 6f 83 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}