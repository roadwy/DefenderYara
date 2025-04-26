
rule Trojan_BAT_Remcos_PPE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 06 07 11 06 91 11 04 11 11 95 61 28 ?? 00 00 0a 9c 11 06 17 58 13 06 } //3
		$a_03_1 = {00 11 09 17 58 20 ff 00 00 00 5f 13 09 11 07 11 04 11 09 95 58 20 ff 00 00 00 5f 13 07 02 11 04 11 09 8f 40 00 00 01 11 04 11 07 8f 40 00 00 01 28 ?? 00 00 06 00 11 04 11 09 95 11 04 11 07 95 58 20 ff 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}