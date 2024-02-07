
rule Backdoor_BAT_Bladabindi_AS_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {08 07 6f 64 90 01 02 0a 8e b7 6f 65 90 01 02 0a 6f 66 90 01 02 0a 07 08 07 6f 67 90 01 02 0a 8e b7 6f 65 90 01 02 0a 6f 68 90 01 02 0a 73 5a 90 01 02 0a 13 06 11 06 07 6f 69 90 01 02 0a 17 73 6a 90 01 02 0a 90 0a 4a 00 72 48 90 01 02 70 11 05 73 63 90 01 02 0a 0c 07 90 00 } //03 00 
		$a_03_1 = {06 16 28 5b 90 01 02 0a 13 04 08 06 1a 06 8e b7 1a 59 6f 5c 90 01 02 0a 11 04 17 59 17 58 8d 3d 90 01 02 01 0d 08 16 6a 90 00 } //01 00 
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_6 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}