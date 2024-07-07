
rule Trojan_AndroidOS_MasterFred_A{
	meta:
		description = "Trojan:AndroidOS/MasterFred.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 68 61 6e 67 65 53 6d 73 44 65 66 61 75 6c 74 41 70 70 41 63 74 69 76 69 74 79 } //1 ChangeSmsDefaultAppActivity
		$a_00_1 = {61 6e 64 72 6f 69 64 5f 6c 6f 61 64 65 72 5f 75 72 6c } //1 android_loader_url
		$a_00_2 = {69 73 4e 4c 45 6e 61 62 6c 65 64 } //1 isNLEnabled
		$a_00_3 = {73 74 61 72 74 4c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } //1 startLoaderActivity
		$a_00_4 = {41 63 63 65 73 73 69 62 69 6c 69 74 79 45 6e 61 62 6c 65 48 69 6e 74 41 63 74 69 76 69 74 79 } //1 AccessibilityEnableHintActivity
		$a_00_5 = {41 63 74 69 76 69 74 79 50 72 65 49 6e 73 74 61 6c 6c } //1 ActivityPreInstall
		$a_00_6 = {41 63 74 69 76 69 74 79 47 65 74 41 63 63 65 73 73 61 62 69 6c 69 74 79 } //1 ActivityGetAccessability
		$a_00_7 = {73 74 61 72 74 5f 77 6f 72 6b 5f 6d 65 3a 20 74 68 72 65 61 64 3a 20 6b 6e 6f 63 6b 69 6e 67 2e 2e 2e } //1 start_work_me: thread: knocking...
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}