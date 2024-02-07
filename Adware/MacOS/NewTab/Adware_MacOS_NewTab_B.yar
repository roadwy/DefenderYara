
rule Adware_MacOS_NewTab_B{
	meta:
		description = "Adware:MacOS/NewTab.B,SIGNATURE_TYPE_MACHOHSTR_EXT,0d 00 0d 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 78 61 74 74 72 } //03 00  getxattr
		$a_02_1 = {43 6f 6e 74 65 6e 74 73 2f 4c 69 62 72 61 72 79 2f 4c 6f 67 69 6e 49 74 65 6d 73 2f 90 02 40 2e 61 70 70 90 00 } //01 00 
		$a_01_2 = {63 6f 6d 2e 61 70 70 6c 65 2e 53 61 66 61 72 69 } //03 00  com.apple.Safari
		$a_01_3 = {63 6f 6e 74 65 6e 74 73 50 72 6f 76 69 64 65 72 } //02 00  contentsProvider
		$a_01_4 = {73 65 74 43 75 72 72 65 6e 74 54 61 62 3a } //03 00  setCurrentTab:
		$a_01_5 = {6f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 56 65 72 73 69 6f 6e } //00 00  operatingSystemVersion
		$a_00_6 = {5d 04 00 00 0c a4 04 00 5c 22 } //00 00 
	condition:
		any of ($a_*)
 
}