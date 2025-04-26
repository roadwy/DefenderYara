
rule Trojan_BAT_Androm_AS_MTB{
	meta:
		description = "Trojan:BAT/Androm.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 "
		
	strings :
		$a_80_0 = {44 41 4c 5f 44 6f 77 6e 6c 6f 61 64 5f 4c 69 73 74 5f 47 65 6e 65 72 61 74 6f 72 } //DAL_Download_List_Generator  3
		$a_80_1 = {69 6d 69 6d 69 6d 69 6d 69 6d } //imimimimim  3
		$a_80_2 = {47 65 74 46 69 6c 65 4e 61 6d 65 42 79 55 52 4c } //GetFileNameByURL  3
		$a_80_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggableAttribute  3
		$a_80_4 = {46 47 45 78 65 63 75 74 65 } //FGExecute  3
		$a_80_5 = {4b 69 6c 6c 54 61 73 6b } //KillTask  3
		$a_80_6 = {71 75 69 74 43 6c 69 63 6b } //quitClick  3
		$a_80_7 = {41 63 74 69 76 69 74 79 5f 4c 6f 67 67 65 72 } //Activity_Logger  3
		$a_80_8 = {57 6f 72 6b 65 72 45 78 65 63 75 74 65 } //WorkerExecute  3
		$a_80_9 = {44 72 6f 70 64 6f 77 6e 4b 69 6c 6c } //DropdownKill  3
		$a_80_10 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3+(#a_80_10  & 1)*3) >=33
 
}