
rule Trojan_Win32_RifDoor_EC_MTB{
	meta:
		description = "Trojan:Win32/RifDoor.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 69 66 6c 65 2e 70 64 62 } //1 rifle.pdb
		$a_01_1 = {67 75 69 66 78 2e 65 78 65 22 20 2f 72 75 6e } //1 guifx.exe" /run
		$a_81_2 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //1 DeleteUrlCacheEntry
		$a_81_3 = {24 64 6f 77 6e 6c 6f 61 64 65 78 65 63 } //1 $downloadexec
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {2f 63 20 64 65 6c 20 2f 71 } //1 /c del /q
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}