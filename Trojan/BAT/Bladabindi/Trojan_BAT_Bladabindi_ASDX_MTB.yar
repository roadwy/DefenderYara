
rule Trojan_BAT_Bladabindi_ASDX_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ASDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 d4 b3 d8 d9 58 5f 58 59 02 73 90 01 01 00 00 0a 0a 73 90 01 01 00 00 0a 0b 28 90 01 01 00 00 0a 38 90 01 02 00 00 03 28 90 01 01 00 00 0a 04 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0d 08 09 1f 20 6f 90 01 01 00 00 0a 38 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}