
rule TrojanDropper_AndroidOS_Flubot_A{
	meta:
		description = "TrojanDropper:AndroidOS/Flubot.A,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 64 65 6d 6f 66 6f 72 6d 61 6c 77 61 72 65 } //10 /demoformalware
		$a_00_1 = {61 64 64 46 42 4c 69 73 74 65 6e 65 72 } //2 addFBListener
		$a_00_2 = {69 73 41 70 70 49 6e 73 74 61 6c 6c 65 64 } //1 isAppInstalled
		$a_00_3 = {69 73 50 61 63 6b 61 67 65 49 6e 73 74 61 6c 6c 65 64 } //1 isPackageInstalled
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=13
 
}