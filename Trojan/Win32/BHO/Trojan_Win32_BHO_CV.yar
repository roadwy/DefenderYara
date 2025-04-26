
rule Trojan_Win32_BHO_CV{
	meta:
		description = "Trojan:Win32/BHO.CV,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 2e 64 6c 6c } //1 GameVersionUpdate.dll
		$a_01_1 = {67 65 74 20 68 74 74 70 3a 2f 2f 25 73 25 73 20 68 74 74 70 2f 31 2e 31 } //1 get http://%s%s http/1.1
		$a_01_2 = {55 72 6c 3d 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 5f 53 65 74 75 70 26 4d 61 63 3d 25 73 26 56 65 72 73 69 6f 6e 3d } //1 Url=GameVersionUpdate_Setup&Mac=%s&Version=
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 31 2e 69 6e 69 } //1 C:\WINDOWS\system32\drivers\etc\service1.ini
		$a_01_4 = {2f 53 74 61 72 74 2e 68 74 6d 3f 73 31 3d 69 6e 69 } //1 /Start.htm?s1=ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}