
rule Trojan_BAT_Remcos_MBIJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 67 68 68 66 67 73 66 66 66 72 66 64 66 64 66 66 64 64 73 68 66 64 61 73 64 66 68 } //01 00  fghhfgsfffrfdfdffddshfdasdfh
		$a_01_1 = {73 67 66 68 6a 66 66 66 66 67 64 68 6a 73 72 66 68 64 64 66 68 66 66 66 61 64 66 73 66 73 73 63 66 67 64 62 } //01 00  sgfhjffffgdhjsrfhddfhfffadfsfsscfgdb
		$a_01_2 = {66 68 66 73 64 73 66 68 66 64 66 68 68 73 } //01 00  fhfsdsfhfdfhhs
		$a_01_3 = {73 66 66 64 66 67 67 66 73 } //01 00  sffdfggfs
		$a_01_4 = {63 64 66 66 66 64 66 61 66 64 66 72 73 66 73 73 68 64 6b 66 66 66 67 68 } //01 00  cdfffdfafdfrsfsshdkfffgh
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00  GetMethods
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}