
rule Trojan_Win64_Blocker_NB_MTB{
	meta:
		description = "Trojan:Win64/Blocker.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 28 83 a0 a8 03 00 00 fd 45 33 c9 4c 8d 44 24 20 48 8d 54 24 48 48 8d 4d 80 e8 eb fd ff ff 8b 44 24 68 48 8b 8d 90 01 00 00 48 33 cc e8 1c 80 00 00 4c 8d 9c 24 a0 02 00 00 49 8b 5b 18 49 8b 7b 20 49 8b e3 } //2
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {77 69 6e 6c 6f 67 73 76 63 2e 65 78 65 } //1 winlogsvc.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}