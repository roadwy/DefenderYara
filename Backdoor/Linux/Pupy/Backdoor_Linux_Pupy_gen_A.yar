
rule Backdoor_Linux_Pupy_gen_A{
	meta:
		description = "Backdoor:Linux/Pupy.gen!A!!Pupy.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {70 75 70 79 6c 69 62 2e 50 75 70 79 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  pupylib.PupyCredentials
		$a_81_1 = {50 75 70 79 54 43 50 53 65 72 76 65 72 } //01 00  PupyTCPServer
		$a_81_2 = {42 49 4e 44 5f 50 41 59 4c 4f 41 44 53 5f 50 41 53 53 57 4f 52 44 } //01 00  BIND_PAYLOADS_PASSWORD
		$a_81_3 = {6e 65 74 77 6f 72 6b 2f 6c 69 62 2f 6c 61 75 6e 63 68 65 72 73 2f } //00 00  network/lib/launchers/
	condition:
		any of ($a_*)
 
}