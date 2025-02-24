
rule Trojan_BAT_LockScreen_ARA_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 43 61 64 69 6c 6c 61 63 4c 6f 63 6b 65 72 2e 70 64 62 } //3 \CadillacLocker.pdb
		$a_01_1 = {5c 52 6f 62 75 78 43 6f 64 65 47 65 6e 65 72 61 74 6f 72 2e 70 64 62 } //3 \RobuxCodeGenerator.pdb
		$a_00_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //2 DisableTaskMgr
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_00_2  & 1)*2) >=5
 
}