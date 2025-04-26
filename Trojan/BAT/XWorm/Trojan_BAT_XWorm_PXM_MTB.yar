
rule Trojan_BAT_XWorm_PXM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 72 85 00 00 70 a2 25 17 08 a2 25 18 72 6a 01 00 70 a2 } //2
		$a_00_1 = {24 32 33 31 30 66 37 35 30 2d 34 36 66 33 2d 34 35 34 30 2d 39 33 33 62 2d 38 65 35 32 65 63 37 61 35 30 36 38 } //2 $2310f750-46f3-4540-933b-8e52ec7a5068
		$a_00_2 = {41 64 64 46 6f 6c 64 65 72 54 6f 44 65 66 65 6e 64 65 72 45 78 63 6c 75 73 69 6f 6e 4c 69 73 74 } //1 AddFolderToDefenderExclusionList
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=5
 
}
rule Trojan_BAT_XWorm_PXM_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.PXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 00 61 00 73 00 74 00 61 00 6e 00 65 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 } //4 Hastane_Proje
		$a_03_1 = {00 04 28 42 00 00 06 26 7e 0d 00 00 04 18 6f ?? 00 00 0a 00 02 03 02 03 02 02 03 05 28 ?? 00 00 06 0a 2b 00 06 2a } //3
		$a_03_2 = {00 02 02 72 97 00 00 70 16 28 ?? 00 00 06 0a 2b 00 06 2a } //2
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_00_0  & 1)*4+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}