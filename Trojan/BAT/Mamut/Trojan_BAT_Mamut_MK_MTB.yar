
rule Trojan_BAT_Mamut_MK_MTB{
	meta:
		description = "Trojan:BAT/Mamut.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_81_0 = {4b 45 45 50 20 49 4e 20 4d 49 4e 44 20 59 4f 55 52 20 50 43 20 49 53 20 47 4f 49 4e 47 20 54 4f 20 42 45 20 44 45 53 54 52 4f 59 45 44 2e } //15 KEEP IN MIND YOUR PC IS GOING TO BE DESTROYED.
		$a_81_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //10 \\.\PhysicalDrive0
		$a_81_2 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //5 DisableRegistryTools
		$a_81_3 = {72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 52 20 2f 66 } //3 reg delete HKCR /f
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //2 DisableTaskMgr
	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=35
 
}