
rule Trojan_BAT_Injuke_MC_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 00 52 00 42 00 71 00 70 00 4b 00 59 00 74 00 53 00 74 00 } //01 00  uRBqpKYtSt
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_2 = {54 00 65 00 73 00 74 00 2d 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 66 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 2e 00 63 00 6f 00 6d 00 } //01 00  Test-Connection facebook.com
		$a_01_3 = {65 00 73 00 61 00 65 00 6c 00 65 00 72 00 2f 00 20 00 67 00 69 00 66 00 6e 00 6f 00 63 00 70 00 69 00 } //01 00  esaeler/ gifnocpi
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_5 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_6 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_7 = {44 6f 46 6f 6f } //00 00  DoFoo
	condition:
		any of ($a_*)
 
}