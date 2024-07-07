
rule TrojanSpy_AndroidOS_Secneo_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Secneo.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 61 73 5f 66 69 6c 65 6f 62 73 65 72 76 65 72 } //1 has_fileobserver
		$a_00_1 = {2f 63 6f 6d 2e 73 65 63 6e 65 6f 2e 74 6d 70 } //1 /com.secneo.tmp
		$a_00_2 = {63 6f 6d 2f 73 65 63 73 68 65 6c 6c 2f 73 65 63 44 61 74 61 2f 46 69 6c 65 73 46 69 6c 65 4f 62 73 65 72 76 65 72 } //1 com/secshell/secData/FilesFileObserver
		$a_00_3 = {50 61 73 73 77 6f 72 64 4f 62 73 65 72 76 65 72 } //1 PasswordObserver
		$a_00_4 = {63 6f 6d 2e 67 73 6f 66 74 2e 41 53 45 50 71 } //1 com.gsoft.ASEPq
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}