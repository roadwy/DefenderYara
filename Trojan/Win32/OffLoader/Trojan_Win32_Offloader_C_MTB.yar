
rule Trojan_Win32_Offloader_C_MTB{
	meta:
		description = "Trojan:Win32/Offloader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 70 00 6c 00 65 00 61 00 73 00 75 00 72 00 65 00 66 00 6c 00 79 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 3f 00 } //2 ://pleasurefly.online/tracker/thank_you.php?
		$a_01_1 = {3a 00 2f 00 2f 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 62 00 6f 00 6e 00 65 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 67 00 6f 00 74 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 } //2 ://languagebone.online/goto.php?
		$a_81_2 = {2f 73 69 6c 65 6e 74 } //1 /silent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}
rule Trojan_Win32_Offloader_C_MTB_2{
	meta:
		description = "Trojan:Win32/Offloader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-2a] 2e 00 63 00 72 00 6f 00 77 00 2f 00 [0-ff] [0-ff] 2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 00 00 67 00 65 00 74 00 [0-2f] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-2a] 2e 00 69 00 6e 00 66 00 6f 00 2f 00 [0-ff] [0-ff] 3d 00 [0-1f] 2e 00 65 00 78 00 65 00 [0-1f] 2e 00 65 00 78 00 65 00 } //3
		$a_02_1 = {68 74 00 74 00 70 73 3a 2f 2f [0-2a] 2e 63 72 6f 77 2f [0-ff] [0-ff] 2f 73 69 6c 65 6e 74 00 00 67 65 74 [0-2f] 68 74 00 74 00 70 73 3a 2f 2f [0-2a] 2e 69 6e 66 6f 2f [0-ff] [0-ff] 3d [0-1f] 2e 65 78 65 [0-1f] 2e 65 78 65 } //3
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  2
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_80_2  & 1)*2) >=5
 
}