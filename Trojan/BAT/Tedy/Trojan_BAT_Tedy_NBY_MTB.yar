
rule Trojan_BAT_Tedy_NBY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 4d 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 02 28 ?? 00 00 06 0c 2b 00 08 } //5
		$a_03_1 = {02 28 07 00 00 06 0a 06 6f ?? 00 00 0a 0b 2b 00 07 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}