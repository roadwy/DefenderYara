
rule Trojan_BAT_TitanStealer_NA_MTB{
	meta:
		description = "Trojan:BAT/TitanStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {08 03 08 03 8e 69 5d 91 9e 00 08 17 58 0c 08 } //5
		$a_81_1 = {4e 65 77 42 6f 74 2e 4c 6f 61 64 65 72 } //1 NewBot.Loader
		$a_81_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_81_3 = {4b 65 79 67 65 6e } //1 Keygen
		$a_81_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_81_5 = {69 6e 6a 65 63 74 6f 72 } //1 injector
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}