
rule Trojan_BAT_Razy_PTFT_MTB{
	meta:
		description = "Trojan:BAT/Razy.PTFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 15 00 00 0a 73 16 00 00 0a 28 90 01 01 00 00 0a 6f 18 00 00 0a 6f 19 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}