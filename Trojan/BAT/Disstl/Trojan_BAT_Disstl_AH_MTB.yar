
rule Trojan_BAT_Disstl_AH_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {74 00 74 00 5a 00 49 00 44 00 31 00 76 00 30 00 76 00 31 00 54 00 71 00 4d 00 57 00 68 00 59 00 64 00 6b 00 4a 00 58 00 62 00 36 00 31 00 2f 00 71 00 4e 00 64 00 7a 00 2f 00 67 00 2b 00 61 00 4d 00 6d 00 66 00 38 00 58 00 45 00 79 00 79 00 72 00 73 00 71 00 66 00 6d 00 6b 00 6b 00 65 00 30 00 44 00 48 00 66 00 49 00 72 00 59 00 78 00 55 00 65 00 79 00 45 00 62 00 72 00 42 00 30 00 32 00 6f 00 } //3 ttZID1v0v1TqMWhYdkJXb61/qNdz/g+aMmf8XEyyrsqfmkke0DHfIrYxUeyEbrB02o
		$a_80_1 = {2f 43 20 2f 73 74 65 78 74 } ///C /stext  3
		$a_80_2 = {64 69 73 63 6f 72 64 } //discord  3
		$a_80_3 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //GetAllNetworkInterfaces  3
		$a_80_4 = {47 65 74 50 68 79 73 69 63 61 6c 41 64 64 72 65 73 73 } //GetPhysicalAddress  3
		$a_80_5 = {57 65 62 68 6f 6f 6b } //Webhook  3
		$a_80_6 = {61 76 61 74 61 72 5f 75 72 6c } //avatar_url  3
	condition:
		((#a_00_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}