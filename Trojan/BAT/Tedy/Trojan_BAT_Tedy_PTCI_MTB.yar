
rule Trojan_BAT_Tedy_PTCI_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PTCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 11 04 2c 0c 72 89 00 00 70 28 90 01 01 00 00 0a 00 00 38 ce 01 00 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}