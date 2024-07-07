
rule Trojan_AndroidOS_SpyAgent_AR{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AR,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 61 73 6b 31 55 6e 69 71 75 65 4e 61 6d 65 } //2 Task1UniqueName
		$a_01_1 = {63 6f 6d 2f 6e 6f 74 6e 75 6c 6c 2f 72 65 6c 65 61 73 65 2f 47 69 7a 6d 6f } //2 com/notnull/release/Gizmo
		$a_01_2 = {6e 6f 74 6e 75 6c 6c 2f 72 65 6c 65 61 73 65 2f 57 65 62 56 } //2 notnull/release/WebV
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}