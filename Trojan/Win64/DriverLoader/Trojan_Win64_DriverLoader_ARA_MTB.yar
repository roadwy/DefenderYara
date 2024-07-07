
rule Trojan_Win64_DriverLoader_ARA_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 79 57 46 48 61 63 6b 5c 43 72 79 4b 69 6c 6c 65 72 5c 4e 45 57 20 42 59 50 41 53 53 5c 77 31 6e 6e 65 72 } //2 \MyWFHack\CryKiller\NEW BYPASS\w1nner
		$a_01_1 = {6c 69 6d 69 74 65 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 77 31 6e 6e 65 72 2e 70 64 62 } //2 limited\x64\Release\w1nner.pdb
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 42 61 74 74 6c 65 2e 6e 65 74 2e 65 78 65 } //2 taskkill /f /im Battle.net.exe
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4d 6f 64 65 72 6e 57 61 72 66 61 72 65 2e 65 78 65 } //2 taskkill /f /im ModernWarfare.exe
		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 63 6f 64 2e 65 78 65 } //2 taskkill /f /im cod.exe
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 73 74 65 61 6d 2e 65 78 65 } //2 taskkill /f /im steam.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}