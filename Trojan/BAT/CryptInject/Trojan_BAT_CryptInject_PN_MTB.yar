
rule Trojan_BAT_CryptInject_PN_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 33 39 39 35 39 61 31 37 2d 30 32 36 61 2d 34 35 62 39 2d 38 63 62 64 2d 64 64 35 62 62 30 64 32 39 38 31 64 } //01 00  $39959a17-026a-45b9-8cbd-dd5bb0d2981d
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 4a 75 6c 69 61 6e 47 39 37 2f 54 65 78 74 45 64 69 74 6f 72 } //01 00  https://github.com/JulianG97/TextEditor
		$a_81_2 = {4d 6f 6e 6f 70 6f 6c 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Monopoly.Properties.Resources
		$a_81_3 = {67 65 74 5f 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 } //01 00  get_qqqqqqqqqqqqqqqqqqqqqqqqqqqqq
		$a_81_4 = {41 20 73 69 6d 70 6c 65 20 77 69 6e 64 6f 77 73 20 66 6f 72 6d 73 20 74 65 78 74 20 65 64 69 74 6f 72 20 77 72 69 74 74 65 6e 20 69 6e 20 43 23 } //01 00  A simple windows forms text editor written in C#
		$a_81_5 = {4d 6f 6e 6f 70 6f 6c 79 } //00 00  Monopoly
	condition:
		any of ($a_*)
 
}