
rule Trojan_BAT_Remcos_RVB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_81_0 = {11 19 11 17 d4 11 4a 6e 11 4d 20 ff 00 00 00 5f 6a 61 d2 9c 11 17 } //1
	condition:
		((#a_81_0  & 1)*1) >=1
 
}