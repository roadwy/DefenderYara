
rule Trojan_BAT_Remcos_REN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.REN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 16 39 9b 00 00 00 26 26 38 9e 00 00 00 20 80 00 00 00 38 9a 00 00 00 38 9f 00 00 00 72 } //01 00 
		$a_03_1 = {06 20 e8 03 00 00 73 90 01 03 0a 0d 08 09 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 08 09 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 08 17 6f 90 01 03 0a 07 08 6f 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}