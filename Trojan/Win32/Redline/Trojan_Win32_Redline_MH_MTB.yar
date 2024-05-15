
rule Trojan_Win32_Redline_MH_MTB{
	meta:
		description = "Trojan:Win32/Redline.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b ca 8b c6 33 d2 f7 f1 8a 04 3a 30 04 2e 46 3b f3 7c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MH_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {01 6c 24 10 c7 44 24 18 00 00 00 00 8b 44 24 24 01 44 24 18 8b 44 24 28 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 } //05 00 
		$a_03_1 = {d3 e8 8b 4c 24 10 03 44 24 30 89 44 24 14 33 44 24 20 33 c8 2b f9 8d 44 24 24 89 4c 24 10 89 7c 24 28 e8 90 01 04 83 eb 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MH_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 00 48 00 51 00 45 00 54 00 43 00 57 00 2e 00 45 00 58 00 45 00 } //01 00  PHQETCW.EXE
		$a_01_1 = {51 00 65 00 6f 00 65 00 65 00 6a 00 70 00 67 00 73 00 67 00 6b 00 6f 00 } //01 00  Qeoeejpgsgko
		$a_01_2 = {4f 00 6d 00 64 00 6d 00 79 00 62 00 72 00 } //01 00  Omdmybr
		$a_01_3 = {0e 00 00 66 00 00 00 00 0e 00 00 00 00 00 d0 6b 00 00 00 10 } //01 00 
		$a_01_4 = {63 6d 64 20 2f 63 20 63 6d 64 20 3c 20 50 6f 69 2e 70 73 74 20 26 20 70 69 6e 67 20 2d 6e 20 35 20 6c 6f 63 4b } //01 00  cmd /c cmd < Poi.pst & ping -n 5 locK
		$a_01_5 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //01 00  DecryptFileA
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //01 00  Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_7 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 5c 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //01 00  System\CurrentControlSet\Control\Session Manager\FileRenameOperations
		$a_01_8 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //01 00  LockResource
		$a_01_9 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 41 } //00 00  GetDiskFreeSpaceA
	condition:
		any of ($a_*)
 
}