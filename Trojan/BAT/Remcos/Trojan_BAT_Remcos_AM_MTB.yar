
rule Trojan_BAT_Remcos_AM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 7e 05 00 00 04 06 7e 05 00 00 04 8e 69 5d 91 61 d2 9c 06 17 58 0a 06 02 8e 69 32 df } //01 00 
		$a_01_1 = {44 65 63 72 79 70 74 42 79 74 65 73 } //01 00  DecryptBytes
		$a_01_2 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}