
rule Trojan_BAT_DarkCloud_AAZW_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AAZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 76 00 6f 00 69 00 63 00 65 00 5f 00 46 00 54 00 46 00 41 00 43 00 33 00 35 00 35 00 2e 00 41 00 5f 00 } //2 Invoice_FTFAC355.A_
	condition:
		((#a_01_0  & 1)*2) >=2
 
}