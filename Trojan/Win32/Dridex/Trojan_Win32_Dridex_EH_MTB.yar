
rule Trojan_Win32_Dridex_EH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {4b 46 36 34 2d 62 69 74 74 6f 34 49 6e 63 6f 67 6e 69 74 6f 49 4b 69 6e 66 } //3 KF64-bitto4IncognitoIKinf
		$a_81_1 = {75 73 61 67 65 64 61 79 2c 61 43 62 61 63 74 65 72 69 6f 6c 6f 67 79 70 68 6f 65 6e 69 78 77 } //3 usageday,aCbacteriologyphoenixw
		$a_81_2 = {72 72 70 69 6f 64 65 2e 70 64 62 } //3 rrpiode.pdb
		$a_81_3 = {4b 35 6e 6c 6e 6f 74 } //3 K5nlnot
		$a_81_4 = {4d 70 72 41 64 6d 69 6e 49 6e 74 65 72 66 61 63 65 54 72 61 6e 73 70 6f 72 74 41 64 64 } //3 MprAdminInterfaceTransportAdd
		$a_81_5 = {43 6f 70 79 45 6e 68 4d 65 74 61 46 69 6c 65 57 } //3 CopyEnhMetaFileW
		$a_81_6 = {53 65 74 75 70 4f 70 65 6e 4c 6f 67 } //3 SetupOpenLog
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}