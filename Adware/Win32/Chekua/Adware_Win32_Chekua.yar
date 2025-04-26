
rule Adware_Win32_Chekua{
	meta:
		description = "Adware:Win32/Chekua,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 64 72 65 61 6d 5c 77 69 6e 7a 79 2e 6c 6f 67 00 51 51 50 43 54 72 61 79 2e 65 78 65 00 6b 78 65 74 72 61 79 2e 65 78 65 } //1
		$a_01_1 = {2e 63 6e 7a 7a 2e 63 6f 6d 2f 73 74 61 74 2e 68 74 6d 3f 69 64 3d } //1 .cnzz.com/stat.htm?id=
		$a_03_2 = {2f 66 73 69 6e 74 66 2f [0-30] 3f 70 75 62 6c 69 63 26 63 6f 64 65 3d } //1
		$a_01_3 = {5c 48 6f 6d 65 53 61 66 65 22 20 2f 76 20 22 53 74 61 72 74 46 6c 61 67 4e 6f 54 69 70 22 } //1 \HomeSafe" /v "StartFlagNoTip"
		$a_01_4 = {3c 42 72 6f 77 73 65 72 49 74 65 6d 20 50 72 6f 63 65 73 73 3d 22 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 } //1 <BrowserItem Process="iexplore.exe"
		$a_01_5 = {5c 48 6f 6d 65 53 61 66 65 5c 73 74 61 72 74 5f 63 6f 6e 66 69 67 2e 78 6d 6c } //1 \HomeSafe\start_config.xml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}