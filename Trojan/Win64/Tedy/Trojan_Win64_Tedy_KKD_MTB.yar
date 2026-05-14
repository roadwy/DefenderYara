
rule Trojan_Win64_Tedy_KKD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 41 6e 74 69 67 72 61 76 69 74 79 52 41 54 5f 53 69 6e 67 6c 65 49 6e 73 74 61 6e 63 65 5f 4d 75 74 65 78 } //5 Global\AntigravityRAT_SingleInstance_Mutex
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 54 20 3e 20 4e 55 4c 20 32 3e 26 31 } //4 taskkill /F /IM chrome.exe /T > NUL 2>&1
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 6d 73 65 64 67 65 2e 65 78 65 20 2f 54 20 3e 20 4e 55 4c 20 32 3e 26 31 } //3 taskkill /F /IM msedge.exe /T > NUL 2>&1
		$a_01_3 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 2a } //2 \Mozilla\Firefox\Profiles\*
		$a_01_4 = {5b 2a 5d 20 53 74 65 61 6c 69 6e 67 3a 20 } //1 [*] Stealing: 
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=15
 
}