
rule Trojan_BAT_Remcos_ABGK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f 1e 00 00 0a 08 17 58 0c 08 02 8e 69 32 e3 07 2a } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_3 = {47 65 74 42 79 74 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}