
rule Trojan_Win32_LummaC_B_MTB{
	meta:
		description = "Trojan:Win32/LummaC.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75 e4 } //01 00 
		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 69 6d 65 6f 75 74 20 2f 6e 6f 62 72 65 61 6b 20 2f 74 20 33 20 26 20 66 73 75 74 69 6c 20 66 69 6c 65 20 73 65 74 5a 65 72 6f 44 61 74 61 20 6f 66 66 73 65 74 3d 30 20 6c 65 6e 67 74 68 3d 25 6c 75 20 22 25 73 22 20 26 20 65 72 61 73 65 20 22 25 73 22 20 26 20 65 78 69 74 } //01 00  cmd.exe /c timeout /nobreak /t 3 & fsutil file setZeroData offset=0 length=%lu "%s" & erase "%s" & exit
		$a_81_2 = {67 73 74 61 74 69 63 2d 6e 6f 64 65 2e 69 6f } //01 00  gstatic-node.io
		$a_81_3 = {54 65 73 6c 61 42 72 6f 77 73 65 72 } //01 00  TeslaBrowser
		$a_81_4 = {2a 2e 65 6d 6c } //01 00  *.eml
		$a_81_5 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 22 25 73 22 } //01 00  powershell -exec bypass "%s"
		$a_81_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
	condition:
		any of ($a_*)
 
}