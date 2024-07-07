
rule Trojan_BAT_Coinminer_JRIMI_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.JRIMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 64 73 53 00 00 0a 0a 73 54 00 00 0a 13 05 11 05 20 00 01 00 00 2b 18 11 05 17 2b 05 11 05 0b 2b 07 6f 90 01 03 0a 2b f4 03 2d 02 2b 09 2b 3a 6f 90 01 03 0a 2b e1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}