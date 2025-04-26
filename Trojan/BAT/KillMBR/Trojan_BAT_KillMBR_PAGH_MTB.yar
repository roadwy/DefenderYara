
rule Trojan_BAT_KillMBR_PAGH_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.PAGH!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \\.\PhysicalDrive0
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 DisableRegistryTools
		$a_01_3 = {59 00 6f 00 75 00 72 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 68 00 61 00 63 00 6b 00 65 00 64 00 } //2 Your System has been hacked
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}