
rule TrojanDownloader_Win32_Hicrazyk_E{
	meta:
		description = "TrojanDownloader:Win32/Hicrazyk.E,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 2e 63 6e 2f 52 5a 61 49 5a 39 51 } //16 t.cn/RZaIZ9Q
		$a_01_1 = {31 38 30 2e 31 35 33 2e 31 34 37 2e 37 33 2f 66 73 69 6e 74 66 2f 63 39 66 32 35 34 39 66 63 65 31 38 66 34 64 63 34 61 65 31 33 64 36 61 36 35 32 37 64 39 63 34 65 2f } //4 180.153.147.73/fsintf/c9f2549fce18f4dc4ae13d6a6527d9c4e/
		$a_01_2 = {2f 6b 3f 70 75 62 6c 69 63 26 63 6f 64 65 3d } //2 /k?public&code=
		$a_01_3 = {72 64 2e 68 74 6d 3f 69 64 3d 31 33 38 34 36 35 39 26 72 3d 68 74 74 70 } //2 rd.htm?id=1384659&r=http
		$a_01_4 = {44 3a 5c 4d 4d 2d 6c 69 61 6f } //1 D:\MM-liao
		$a_01_5 = {5c 64 72 65 61 6d 5c 47 4a 32 } //1 \dream\GJ2
		$a_03_6 = {64 72 65 61 6d 5c [0-06] 65 78 70 6c 6f 72 65 72 5f 6b } //1
		$a_01_7 = {48 6f 6d 65 53 61 66 65 5c 73 74 61 72 74 5f 63 6f 6e 66 69 67 2e 78 6d 6c } //1 HomeSafe\start_config.xml
	condition:
		((#a_01_0  & 1)*16+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1) >=18
 
}