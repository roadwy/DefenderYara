
rule Trojan_BAT_KillMBR_ARAS_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 43 20 72 6d 64 69 72 20 2f 73 20 2f 71 20 43 3a 5c 57 69 6e 64 6f 77 73 } ///C rmdir /s /q C:\Windows  2
		$a_80_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  2
		$a_80_2 = {5c 52 65 6c 65 61 73 65 5c 59 50 44 2e 70 64 62 } //\Release\YPD.pdb  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}
rule Trojan_BAT_KillMBR_ARAS_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 54 4f 44 20 54 72 6f 6a 61 6e 20 63 6c 61 73 73 5c 54 4f 44 5c 54 4f 44 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 4f 44 2e 70 64 62 } //2 \TOD Trojan class\TOD\TOD\obj\Debug\TOD.pdb
		$a_01_1 = {72 65 67 5f 64 65 73 74 72 6f 79 } //2 reg_destroy
		$a_01_2 = {6d 62 72 5f 64 65 73 74 72 6f 79 } //2 mbr_destroy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}