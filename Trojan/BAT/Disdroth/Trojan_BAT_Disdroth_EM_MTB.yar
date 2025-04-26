
rule Trojan_BAT_Disdroth_EM_MTB{
	meta:
		description = "Trojan:BAT/Disdroth.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 1f a2 0b 09 07 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 42 00 00 00 1a 00 00 00 1a 00 00 00 3f 00 00 00 1f 00 00 00 08 00 00 00 66 00 00 00 08 00 00 00 15 00 00 00 } //1
		$a_81_1 = {53 79 6e 63 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 SyncController
		$a_81_2 = {4c 69 76 65 46 69 6c 65 2e 53 79 6e 63 4f 70 73 } //1 LiveFile.SyncOps
		$a_81_3 = {4f 70 65 6e 57 69 74 68 44 65 66 61 75 6c 74 50 72 6f 67 72 61 6d } //1 OpenWithDefaultProgram
		$a_81_4 = {57 44 53 79 6e 63 2e 64 6c 6c } //1 WDSync.dll
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}