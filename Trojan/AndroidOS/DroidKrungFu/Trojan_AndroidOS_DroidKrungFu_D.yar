
rule Trojan_AndroidOS_DroidKrungFu_D{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {65 78 65 63 53 79 73 49 6e 73 74 61 6c 6c } //1 execSysInstall
		$a_00_1 = {6c 69 6c 68 65 72 6d 69 74 43 6f 72 65 } //1 lilhermitCore
		$a_00_2 = {65 78 65 63 55 70 42 69 6e } //1 execUpBin
		$a_00_3 = {44 49 41 4c 4f 47 5f 47 52 41 4e 54 5f 53 55 } //1 DIALOG_GRANT_SU
		$a_00_4 = {74 72 79 49 6e 73 74 42 69 6e } //1 tryInstBin
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}