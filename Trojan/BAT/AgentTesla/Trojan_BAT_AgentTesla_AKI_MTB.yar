
rule Trojan_BAT_AgentTesla_AKI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 14 14 28 90 01 03 0a 6f 90 01 03 0a 16 9a 14 72 90 01 03 70 17 8d 90 01 03 01 25 16 03 a2 25 13 1c 14 14 17 8d 90 01 03 01 25 16 17 9c 25 13 1d 28 90 01 03 0a 11 1d 16 91 2d 02 2b 0b 11 1c 16 9a 90 00 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {52 65 76 65 72 73 65 } //Reverse  2
		$a_80_3 = {47 65 74 54 79 70 65 } //GetType  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}