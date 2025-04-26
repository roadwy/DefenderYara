
rule Trojan_BAT_Downloader_IHU_MTB{
	meta:
		description = "Trojan:BAT/Downloader.IHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 62 31 34 34 37 36 35 34 2d 36 66 38 35 2d 34 37 62 31 2d 38 66 35 37 2d 66 65 61 64 30 65 39 61 34 63 35 32 } //10 $b1447654-6f85-47b1-8f57-fead0e9a4c52
		$a_01_1 = {45 6e 74 72 79 } //1 Entry
		$a_01_2 = {45 78 65 63 75 74 65 } //1 Execute
		$a_01_3 = {46 65 74 63 68 46 69 6c 65 73 } //1 FetchFiles
		$a_01_4 = {4d 65 74 68 6f 64 49 6e 66 6f } //1 MethodInfo
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}