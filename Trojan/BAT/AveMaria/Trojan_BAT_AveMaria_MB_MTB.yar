
rule Trojan_BAT_AveMaria_MB_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 08 2b 09 06 18 6f 90 01 03 0a 2b 07 6f 90 01 03 0a 2b f0 20 90 01 04 8d 90 01 03 01 25 d0 90 01 03 04 28 90 01 03 0a 0d 2b 03 0c 2b d1 06 6f 90 01 03 0a 09 16 09 8e 69 6f 90 01 03 0a 13 04 de 14 90 00 } //01 00 
		$a_01_1 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //01 00  DynamicInvoke
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00  GetCurrentProcess
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}