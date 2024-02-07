
rule Trojan_BAT_ZulsyCrypt_A_MTB{
	meta:
		description = "Trojan:BAT/ZulsyCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 09 20 ff 00 00 00 9c 09 17 58 0d 09 08 8e 69 } //02 00 
		$a_01_1 = {25 17 58 13 0a 91 08 61 d2 9c 09 17 5f } //01 00 
		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //01 00  GetDelegateForFunctionPointer
		$a_01_3 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //00 00  get_EntryPoint
	condition:
		any of ($a_*)
 
}