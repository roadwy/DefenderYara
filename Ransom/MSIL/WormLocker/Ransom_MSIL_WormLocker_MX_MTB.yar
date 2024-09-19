
rule Ransom_MSIL_WormLocker_MX_MTB{
	meta:
		description = "Ransom:MSIL/WormLocker.MX!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 6f 72 6d 4c 6f 63 6b 65 72 } //5 WormLocker
		$a_01_1 = {77 00 6f 00 72 00 6d 00 5f 00 74 00 6f 00 6f 00 6c 00 2e 00 73 00 79 00 73 00 } //1 worm_tool.sys
		$a_01_2 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}