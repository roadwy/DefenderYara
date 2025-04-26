
rule Trojan_BAT_OrcusRat_NEAA_MTB{
	meta:
		description = "Trojan:BAT/OrcusRat.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {02 17 9a 72 6d 00 00 70 02 18 9a 28 16 00 00 0a 28 02 00 00 06 2a 06 } //5
		$a_01_1 = {4f 00 72 00 63 00 75 00 73 00 2e 00 47 00 6f 00 6c 00 65 00 6d 00 } //4 Orcus.Golem
		$a_01_2 = {2f 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 46 00 69 00 6c 00 65 00 } //4 /protectFile
		$a_01_3 = {2f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 43 00 6c 00 69 00 65 00 6e 00 74 00 41 00 6e 00 64 00 45 00 78 00 69 00 74 00 } //4 /launchClientAndExit
		$a_01_4 = {2f 00 77 00 61 00 74 00 63 00 68 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //4 /watchProcess
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=21
 
}