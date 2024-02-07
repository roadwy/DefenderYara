
rule Trojan_BAT_Discord_ABG_MTB{
	meta:
		description = "Trojan:BAT/Discord.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0a 05 2d 08 06 7e 63 90 01 02 04 60 0a 05 6e 20 00 90 01 02 80 6e 5f 2c 08 06 7e 64 90 01 02 04 60 0a 02 04 61 03 04 61 5f 6e 20 00 90 01 02 80 6e 5f 2c 08 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_6 = {52 65 67 69 73 74 72 79 4b 65 79 } //00 00  RegistryKey
	condition:
		any of ($a_*)
 
}