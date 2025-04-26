
rule Trojan_BAT_AveMaria_NEBD_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 67 00 69 00 73 00 68 00 2e 00 63 00 66 00 67 00 } //5 logish.cfg
		$a_01_1 = {47 6c 61 64 69 61 74 6f 72 } //5 Gladiator
		$a_01_2 = {41 62 79 73 73 57 61 6c 6b 65 72 } //5 AbyssWalker
		$a_01_3 = {4e 65 65 64 47 6f 6c 6b 6f 6e 64 61 } //5 NeedGolkonda
		$a_01_4 = {67 65 74 5f 53 6f 72 63 65 72 65 72 } //5 get_Sorcerer
		$a_01_5 = {67 65 74 5f 4e 65 63 72 6f 6d 61 6e 63 65 72 } //5 get_Necromancer
		$a_01_6 = {6b 69 6c 6c 42 75 74 74 } //5 killButt
		$a_01_7 = {4e 65 65 64 4b 65 72 6e 6f 6e } //5 NeedKernon
		$a_01_8 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 57 00 68 00 65 00 72 00 65 00 20 00 50 00 61 00 72 00 65 00 6e 00 74 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 44 00 3d 00 7b 00 30 00 7d 00 } //5 Select * From Win32_Process Where ParentProcessID={0}
		$a_01_9 = {47 65 74 43 68 69 6c 64 50 72 6f 63 65 73 73 65 73 } //1 GetChildProcesses
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*1) >=46
 
}