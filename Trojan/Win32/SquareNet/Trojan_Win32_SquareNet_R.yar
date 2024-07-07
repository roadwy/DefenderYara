
rule Trojan_Win32_SquareNet_R{
	meta:
		description = "Trojan:Win32/SquareNet.R,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {73 00 76 00 63 00 76 00 6d 00 78 00 2e 00 65 00 78 00 65 00 } //4 svcvmx.exe
		$a_01_1 = {63 74 3d 25 31 26 64 61 74 61 75 70 3d 25 32 26 63 70 78 3d 25 33 26 73 76 63 76 6d 78 3d 25 34 26 71 64 63 6f 6d 73 76 63 3d 25 35 26 73 7a 70 73 72 76 3d 25 36 26 73 70 6c 73 72 76 3d 25 37 } //3 ct=%1&dataup=%2&cpx=%3&svcvmx=%4&qdcomsvc=%5&szpsrv=%6&splsrv=%7
		$a_01_2 = {45 3a 5c 73 76 63 76 6d 78 5c 62 75 69 6c 64 5c 52 65 6c 65 61 73 65 5c 73 76 63 76 6d 78 32 2e 65 78 65 2e 70 64 62 } //3 E:\svcvmx\build\Release\svcvmx2.exe.pdb
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 70 74 39 2e 63 6f 6d 2f 61 70 69 2f 71 7a 6d 64 } //2 http://www.gpt9.com/api/qzmd
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 69 75 6c 69 61 6e 67 73 68 75 2e 63 6f 6d 2f 63 6c 69 65 6e 69 6d 70 72 6f 78 79 38 } //2 http://www.liuliangshu.com/clienimproxy8
		$a_01_5 = {43 6c 6f 6e 65 28 29 20 69 73 20 6e 6f 74 20 69 6d 70 6c 65 6d 65 6e 74 65 64 20 79 65 74 2e } //1 Clone() is not implemented yet.
		$a_01_6 = {46 6f 72 74 69 43 6c 69 65 6e 74 56 69 72 75 73 43 6c 65 61 6e 65 72 2e 65 78 65 } //1 FortiClientVirusCleaner.exe
		$a_01_7 = {4e 6f 72 6d 61 6e 5f 4d 61 6c 77 61 72 65 5f 43 6c 65 61 6e 65 72 2e 65 78 65 } //1 Norman_Malware_Cleaner.exe
		$a_01_8 = {53 6f 70 68 6f 73 20 55 49 2e 65 78 65 } //1 Sophos UI.exe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}