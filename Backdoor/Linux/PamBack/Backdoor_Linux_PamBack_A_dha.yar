
rule Backdoor_Linux_PamBack_A_dha{
	meta:
		description = "Backdoor:Linux/PamBack.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 72 72 6f 72 20 53 65 72 76 69 63 65 55 6e 6b 6e 6f 77 6e 2d 3e 25 73 } //01 00  error ServiceUnknown->%s
		$a_01_1 = {75 6e 69 78 5f 73 65 74 63 72 65 64 5f 72 65 74 75 72 6e } //03 00  unix_setcred_return
		$a_03_2 = {0f b7 ff 48 8d 05 90 01 04 48 c1 e7 90 01 01 48 01 c7 0f b7 57 90 01 01 66 85 d2 90 01 02 31 c0 90 01 04 4c 8b 47 08 0f b7 c8 89 c2 32 17 83 c0 01 41 32 14 08 88 14 0e 0f b7 57 02 66 39 c2 90 00 } //03 00 
		$a_03_3 = {31 d2 4c 89 e7 e8 90 01 04 85 c0 89 c3 90 01 02 48 8b 4d 90 01 01 48 85 c9 90 01 02 0f b6 01 3c 2d 90 01 02 3c 2b 90 01 02 48 89 ca 44 89 f6 4c 89 e7 90 00 } //00 00 
		$a_00_4 = {5d 04 00 00 74 } //07 05 
	condition:
		any of ($a_*)
 
}