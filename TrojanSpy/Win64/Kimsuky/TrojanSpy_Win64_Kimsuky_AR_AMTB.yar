
rule TrojanSpy_Win64_Kimsuky_AR_AMTB{
	meta:
		description = "TrojanSpy:Win64/Kimsuky.AR!AMTB,SIGNATURE_TYPE_PEHSTR,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 4a 6f 68 6e 44 6f 65 5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 6e 7a 76 77 61 6e 2e 6c 6f 67 } //5 C:\Documents and Settings\JohnDoe\Local Settings\Application Data\nzvwan.log
		$a_01_1 = {25 73 5c 6e 7a 76 77 61 6e 2e 6c 6f 67 } //5 %s\nzvwan.log
		$a_01_2 = {62 61 62 79 2e 64 6c 6c } //5 baby.dll
		$a_01_3 = {63 68 72 6f 6d 65 2e 65 78 65 } //5 chrome.exe
		$a_01_4 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //2 ReflectiveLoader
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //2 CreateRemoteThread
		$a_01_6 = {43 72 65 61 74 65 46 69 6c 65 57 } //2 CreateFileW
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=26
 
}