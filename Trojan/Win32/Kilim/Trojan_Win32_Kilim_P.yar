
rule Trojan_Win32_Kilim_P{
	meta:
		description = "Trojan:Win32/Kilim.P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 70 69 6e 67 6a 73 2f 3f 6b 3d [0-0f] 2c 20 22 70 69 6e 67 6a 73 2e 6a 73 22 } //1
		$a_03_1 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 [0-08] 5f 4c 69 6e 6b 2c 20 22 (62 67|63 72 78) 2e 74 78 74 22 2c 20 33 2c 20 31 29 } //1
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //1 taskkill /IM chrome.exe /F
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}