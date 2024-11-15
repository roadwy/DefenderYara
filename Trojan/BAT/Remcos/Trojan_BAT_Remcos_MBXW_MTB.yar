
rule Trojan_BAT_Remcos_MBXW_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 09 09 11 05 07 11 05 91 11 04 11 09 95 61 28 ?? 00 00 0a 9c 11 05 17 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}