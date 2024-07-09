
rule Adware_MacOS_NewTab_B{
	meta:
		description = "Adware:MacOS/NewTab.B,SIGNATURE_TYPE_MACHOHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 78 61 74 74 72 } //1 getxattr
		$a_02_1 = {43 6f 6e 74 65 6e 74 73 2f 4c 69 62 72 61 72 79 2f 4c 6f 67 69 6e 49 74 65 6d 73 2f [0-40] 2e 61 70 70 } //3
		$a_01_2 = {63 6f 6d 2e 61 70 70 6c 65 2e 53 61 66 61 72 69 } //1 com.apple.Safari
		$a_01_3 = {63 6f 6e 74 65 6e 74 73 50 72 6f 76 69 64 65 72 } //3 contentsProvider
		$a_01_4 = {73 65 74 43 75 72 72 65 6e 74 54 61 62 3a } //2 setCurrentTab:
		$a_01_5 = {6f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 56 65 72 73 69 6f 6e } //3 operatingSystemVersion
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*3) >=13
 
}