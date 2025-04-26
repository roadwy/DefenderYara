
rule Trojan_Win32_TrickBot_ibt{
	meta:
		description = "Trojan:Win32/TrickBot!ibt,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 50 72 6f 6a 65 63 74 73 5c 57 65 62 49 6e 6a 65 63 74 5c 62 69 6e 5c 78 38 36 5c 52 65 6c 65 61 73 65 5f 6e 6f 6c 6f 67 73 5c 70 61 79 6c 6f 61 64 33 32 2e 70 64 62 } //3 F:\Projects\WebInject\bin\x86\Release_nologs\payload32.pdb
		$a_01_1 = {6d 69 63 72 6f 73 6f 66 74 65 64 67 65 63 70 2e 65 78 65 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 66 69 72 65 66 6f 78 2e 65 78 65 20 63 68 72 6f 6d 65 2e 65 78 65 } //1 microsoftedgecp.exe iexplore.exe firefox.exe chrome.exe
		$a_01_2 = {03 da 8b 37 03 f2 33 c9 8a 06 c1 c9 0d 0f be c0 03 c8 46 8a 06 84 c0 75 f1 81 f9 8e 4e 0e ec 74 18 81 f9 aa fc 0d 7c 74 10 81 f9 54 ca af 91 74 08 81 f9 ef ce e0 60 75 5b 0f b7 03 8b 75 e0 8d 04 82 03 46 1c 81 f9 8e 4e 0e ec 75 09 8b 00 03 c2 89 45 f0 eb 31 81 f9 aa fc 0d 7c 75 09 } //2
		$a_01_3 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c6 ff ff 00 00 42 66 85 f6 75 e3 81 f9 5b bc 4a 6a 0f 85 cb 00 00 00 8b 53 10 c7 45 fc 04 00 00 00 8b 42 3c 8b 44 10 78 03 c2 89 45 e0 8b 78 20 8b 58 24 03 fa } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}