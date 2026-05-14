
rule Trojan_Win64_Lummastealer_RR_MTB{
	meta:
		description = "Trojan:Win64/Lummastealer.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_00_0 = {41 00 44 00 4d 00 51 00 43 00 4d 00 44 00 } //1 ADMQCMD
		$a_00_1 = {43 00 41 00 42 00 49 00 4e 00 45 00 54 00 } //1 CABINET
		$a_00_2 = {45 00 58 00 54 00 52 00 41 00 43 00 54 00 4f 00 50 00 54 00 } //1 EXTRACTOPT
		$a_00_3 = {50 00 41 00 43 00 4b 00 49 00 4e 00 53 00 54 00 53 00 50 00 41 00 43 00 45 00 } //1 PACKINSTSPACE
		$a_00_4 = {50 00 4f 00 53 00 54 00 52 00 55 00 4e 00 50 00 52 00 4f 00 47 00 52 00 41 00 4d 00 } //1 POSTRUNPROGRAM
		$a_00_5 = {52 00 45 00 42 00 4f 00 4f 00 54 00 } //1 REBOOT
		$a_00_6 = {52 00 55 00 4e 00 50 00 52 00 4f 00 47 00 52 00 41 00 4d 00 } //1 RUNPROGRAM
		$a_00_7 = {53 00 48 00 4f 00 57 00 57 00 49 00 4e 00 44 00 4f 00 57 00 } //1 SHOWWINDOW
		$a_00_8 = {55 00 50 00 52 00 4f 00 4d 00 50 00 54 00 } //1 UPROMPT
		$a_00_9 = {55 00 53 00 52 00 51 00 43 00 4d 00 44 00 } //1 USRQCMD
		$a_01_10 = {73 63 2e 65 78 65 } //1 sc.exe
		$a_03_11 = {63 6d 64 20 2f 76 20 2f 63 20 53 65 74 20 [0-07] 3d 63 6d 64 20 26 20 21 90 1b 00 21 20 3c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_03_11  & 1)*1) >=12
 
}
rule Trojan_Win64_Lummastealer_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Lummastealer.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 } //1 System\CurrentControlSet\Control\Session Manager
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 61 64 76 70 61 63 6b 2e 64 6c 6c 2c 44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 20 22 25 73 22 } //1 rundll32.exe %sadvpack.dll,DelNodeRunDLL32 "%s"
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_3 = {77 65 78 74 72 61 63 74 5f 63 6c 65 61 6e 75 70 25 64 } //1 wextract_cleanup%d
		$a_01_4 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //1 PendingFileRenameOperations
		$a_01_5 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 5c 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //1 System\CurrentControlSet\Control\Session Manager\FileRenameOperations
		$a_01_6 = {73 63 2e 65 78 65 20 2f 3f 64 75 66 79 33 38 37 39 34 79 66 68 73 6a 64 68 66 38 } //1 sc.exe /?dufy38794yfhsjdhf8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}