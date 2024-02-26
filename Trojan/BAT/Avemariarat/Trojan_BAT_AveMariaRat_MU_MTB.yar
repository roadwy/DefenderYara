
rule Trojan_BAT_AveMariaRat_MU_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_1 = {55 00 70 00 6d 00 72 00 73 00 69 00 61 00 74 00 62 00 63 00 7a 00 70 00 70 00 6e 00 64 00 61 00 75 00 61 00 79 00 6a 00 64 00 72 00 61 00 } //01 00  Upmrsiatbczppndauayjdra
		$a_01_2 = {44 65 6c 65 74 65 49 73 73 75 65 72 } //01 00  DeleteIssuer
		$a_01_3 = {3a 00 2f 00 2f 00 32 00 2e 00 35 00 36 00 2e 00 35 00 36 00 2e 00 31 00 31 00 34 00 2f 00 } //01 00  ://2.56.56.114/
		$a_01_4 = {52 65 73 74 61 72 74 49 73 73 75 65 72 } //01 00  RestartIssuer
		$a_01_5 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}