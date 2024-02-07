
rule Trojan_Win64_Spyboy_AA_MTB{
	meta:
		description = "Trojan:Win64/Spyboy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 63 6f 6e 6e 65 63 74 54 6f 5a 65 6d 61 44 65 76 69 63 65 } //01 00  main.connectToZemaDevice
		$a_01_1 = {6d 61 69 6e 2e 64 65 74 65 63 74 45 44 52 } //01 00  main.detectEDR
		$a_01_2 = {6d 61 69 6e 2e 6c 6f 61 64 44 72 69 76 65 72 } //01 00  main.loadDriver
		$a_01_3 = {6d 61 69 6e 2e 64 72 6f 70 44 72 69 76 65 72 } //01 00  main.dropDriver
		$a_01_4 = {6d 61 69 6e 2e 45 6e 61 62 6c 65 50 72 69 76 69 6c 65 67 65 } //00 00  main.EnablePrivilege
	condition:
		any of ($a_*)
 
}