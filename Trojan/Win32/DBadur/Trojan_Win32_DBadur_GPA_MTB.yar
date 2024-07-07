
rule Trojan_Win32_DBadur_GPA_MTB{
	meta:
		description = "Trojan:Win32/DBadur.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 2d 73 63 72 69 70 74 73 2e 6f 6e 6c 69 6e 65 2f 66 69 6c 65 } //1 x-scripts.online/file
		$a_01_1 = {41 5f 53 63 72 69 70 74 44 69 72 } //1 A_ScriptDir
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
		$a_01_3 = {69 6e 6a 65 63 74 44 61 74 61 } //1 injectData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}