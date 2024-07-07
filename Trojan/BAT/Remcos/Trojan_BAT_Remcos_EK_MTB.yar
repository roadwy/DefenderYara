
rule Trojan_BAT_Remcos_EK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 1e 5b 8d 1a 00 00 01 0b 16 0c 2b 17 07 08 06 08 1e 5a 1e 6f 90 01 03 0a 18 28 90 01 03 0a 9c 08 17 58 0c 08 07 8e 69 17 59 31 e1 90 09 0b 00 28 90 01 03 0a 0a 06 6f 90 00 } //10
		$a_81_1 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}