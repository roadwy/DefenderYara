
rule Trojan_Win32_Merlos{
	meta:
		description = "Trojan:Win32/Merlos,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {7a 3a 5c 70 72 6f 6a 65 63 74 32 30 31 32 5c 72 65 6d 6f 74 65 63 6f 6e 74 72 6f 6c 5c 77 69 6e 68 74 74 70 6e 65 74 5c 63 71 67 61 65 6e 5c 61 70 70 5c 69 6e 73 74 61 6c 6c 73 63 72 69 70 74 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 49 6e 73 74 61 6c 6c 53 63 72 69 70 74 2e 70 64 62 } //1 z:\project2012\remotecontrol\winhttpnet\cqgaen\app\installscript\objfre_wxp_x86\i386\InstallScript.pdb
		$a_01_1 = {61 6b 65 53 69 67 6e 42 75 66 66 65 72 } //1 akeSignBuffer
		$a_01_2 = {7a 3a 5c 70 72 6f 6a 65 63 74 32 30 31 32 5c 72 65 6d 6f 74 65 63 6f 6e 74 72 6f 6c 5c 77 69 6e 68 74 74 70 6e 65 74 5c 61 6d 63 79 5c 61 70 70 5c 77 69 6e 37 5c 73 65 72 76 69 63 65 61 70 70 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 53 65 72 76 69 63 65 41 70 70 2e 70 64 62 } //1 z:\project2012\remotecontrol\winhttpnet\amcy\app\win7\serviceapp\objfre_wxp_x86\i386\ServiceApp.pdb
		$a_01_3 = {c7 00 01 23 45 67 c7 40 04 89 ab cd ef c7 40 08 fe dc ba 98 c7 40 0c 76 54 32 10 } //1
		$a_03_4 = {42 42 41 66 83 3a 00 75 ?? 8d 44 48 fe 85 c9 74 ?? 0f b7 08 66 85 c9 74 } //1
		$a_01_5 = {73 75 70 65 72 6d 61 6e 35 } //1 superman5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}