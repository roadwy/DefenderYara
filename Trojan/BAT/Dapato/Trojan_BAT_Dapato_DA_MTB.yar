
rule Trojan_BAT_Dapato_DA_MTB{
	meta:
		description = "Trojan:BAT/Dapato.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 0b 02 6f 90 01 03 0a 0c 2b 32 02 07 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 da 0d 06 09 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 07 28 90 01 03 06 d6 0b 07 08 32 ca 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}