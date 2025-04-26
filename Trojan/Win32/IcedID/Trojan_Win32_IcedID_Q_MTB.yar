
rule Trojan_Win32_IcedID_Q_MTB{
	meta:
		description = "Trojan:Win32/IcedID.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 65 73 65 72 74 5c 6e 65 61 72 5c 44 61 72 6b } //3 Desert\near\Dark
		$a_81_1 = {63 6c 61 73 73 55 6e 74 69 6c 2e 70 64 62 } //3 classUntil.pdb
		$a_81_2 = {47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 } //3 GetVolumeInformationA
		$a_81_3 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //3 GetStartupInfoA
		$a_81_4 = {50 6f 73 74 4d 65 73 73 61 67 65 41 } //3 PostMessageA
		$a_81_5 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 } //3 GetUserObjectInformationA
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}