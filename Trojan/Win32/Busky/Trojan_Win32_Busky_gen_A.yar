
rule Trojan_Win32_Busky_gen_A{
	meta:
		description = "Trojan:Win32/Busky.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,27 00 1f 00 09 00 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //10 URLDownloadToCacheFileA
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 41 64 77 61 72 65 44 69 73 61 62 6c 65 4b 65 79 34 } //3 SOFTWARE\AdwareDisableKey4
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 41 64 77 61 72 65 44 69 73 61 62 6c 65 4b 65 79 33 } //3 SOFTWARE\AdwareDisableKey3
		$a_01_4 = {68 74 74 70 3a 2f 2f 32 30 37 2e 32 32 36 2e 31 37 37 2e 31 30 38 2f 73 63 2e 65 78 65 } //3 http://207.226.177.108/sc.exe
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 7a 61 62 6f 73 61 6c 74 64 2e 62 69 7a 2f 77 61 66 75 67 69 3f 69 64 3d 43 4f 4d 50 49 44 48 45 52 45 26 77 3d 57 45 42 4d 49 44 48 45 52 45 26 73 74 65 70 3d } //3 http://www.zabosaltd.biz/wafugi?id=COMPIDHERE&w=WEBMIDHERE&step=
		$a_02_6 = {fe ff ff 68 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 3a c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 36 } //4
		$a_02_7 = {fe ff ff 2e c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 45 c6 85 ?? ?? ff ff 49 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 51 c6 85 ?? ?? ff ff 67 } //4
		$a_02_8 = {fe ff ff 61 c6 85 ?? ?? ff ff 48 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 36 c6 85 ?? ?? ff ff 62 c6 85 ?? ?? ff ff 59 c6 85 ?? ?? ff ff 47 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 00 } //4
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_02_6  & 1)*4+(#a_02_7  & 1)*4+(#a_02_8  & 1)*4) >=31
 
}