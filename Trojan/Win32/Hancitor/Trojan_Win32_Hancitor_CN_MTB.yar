
rule Trojan_Win32_Hancitor_CN_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 45 58 54 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64 28 78 36 34 29 } //5 GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)
		$a_01_1 = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 45 58 54 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64 28 78 33 32 29 } //5 GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)
		$a_01_2 = {68 74 74 70 3a 2f 2f 61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //1 http://api.ipify.org
		$a_01_3 = {52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 73 74 61 72 74 } //1 Rundll32.exe %s, start
		$a_01_4 = {57 69 6e 48 6f 73 74 33 32 } //1 WinHost32
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}