
rule Trojan_AndroidOS_Xloader_I3{
	meta:
		description = "Trojan:AndroidOS/Xloader.I3,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 77 61 74 74 65 66 75 6e 6b 6d 65 2e 2e 2e } //1 ==========wattefunkme...
		$a_01_1 = {65 78 74 72 61 63 74 44 65 78 73 20 6e 75 6d 62 65 72 4f 66 44 65 78 73 3a 25 64 } //1 extractDexs numberOfDexs:%d
		$a_01_2 = {73 68 65 6c 6c 20 63 72 65 61 74 65 43 6c 61 73 73 4c 6f 61 64 65 72 20 73 74 65 70 20 33 3a 25 64 } //1 shell createClassLoader step 3:%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}