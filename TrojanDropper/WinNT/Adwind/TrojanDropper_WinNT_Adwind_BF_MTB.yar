
rule TrojanDropper_WinNT_Adwind_BF_MTB{
	meta:
		description = "TrojanDropper:WinNT/Adwind.BF!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 71 70 68 6f 61 72 64 6c 65 2f 4d 68 74 75 6f 72 6a 73 62 76 78 } //1 eqphoardle/Mhtuorjsbvx
		$a_00_1 = {72 69 6c 65 73 69 67 61 76 66 2e 6a 73 } //1 rilesigavf.js
		$a_00_2 = {72 65 73 6f 75 72 63 65 73 2f 70 74 70 7a 6e 6a 6c 6e 64 72 } //1 resources/ptpznjlndr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}