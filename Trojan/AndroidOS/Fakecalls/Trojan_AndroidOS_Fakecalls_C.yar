
rule Trojan_AndroidOS_Fakecalls_C{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 77 73 65 70 65 64 2e 77 77 33 30 } //2 com.wseped.ww30
		$a_01_1 = {6f 70 65 6e 71 6a 61 61 6e 71 6e 61 75 74 68 3a 2f 2f 68 65 6c 6c 6f } //1 openqjaanqnauth://hello
		$a_01_2 = {4d 53 47 5f 4c 4f 41 44 5f 4a 4f 42 5f 53 54 41 52 54 } //1 MSG_LOAD_JOB_START
		$a_01_3 = {73 65 74 42 74 6e 43 4c 69 63 6b } //1 setBtnCLick
		$a_01_4 = {4b 5f 46 49 52 53 54 5f 4c 55 4e 43 48 } //1 K_FIRST_LUNCH
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}