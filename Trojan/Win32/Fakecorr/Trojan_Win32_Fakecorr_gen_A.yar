
rule Trojan_Win32_Fakecorr_gen_A{
	meta:
		description = "Trojan:Win32/Fakecorr.gen!A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 66 78 32 30 30 39 73 65 74 75 70 2e 65 78 65 } //1 ffx2009setup.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 66 69 6c 65 66 69 78 70 72 6f 2e 63 6f 6d 2f 70 75 62 6c 69 63 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 63 6d 64 3d } //1 http://filefixpro.com/public/download.php?cmd=
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 4f 57 5c 6b 65 79 62 6f 61 72 64 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\WOW\keyboard
		$a_01_3 = {57 69 6e 64 6f 77 73 20 64 65 74 65 63 74 65 64 20 74 68 61 74 20 73 6f 6d 65 20 6f 66 20 79 6f 75 72 20 4d 53 20 4f 66 66 69 63 65 20 61 6e 64 20 6d 65 64 69 61 20 66 69 6c 65 73 20 61 72 65 20 63 6f 72 72 75 70 74 65 64 2e 20 43 6c 69 63 6b 20 68 65 72 65 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 20 72 65 63 6f 6d 6d 65 6e 64 65 64 20 66 69 6c 65 20 72 65 70 61 69 72 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e } //1 Windows detected that some of your MS Office and media files are corrupted. Click here to download and install recommended file repair application.
		$a_01_4 = {57 69 6e 64 6f 77 73 20 46 69 6c 65 20 50 72 6f 74 65 63 74 69 6f 6e } //1 Windows File Protection
		$a_01_5 = {50 6c 65 61 73 65 2c 20 72 65 67 69 73 74 65 72 20 79 6f 75 72 20 63 6f 70 79 20 6f 66 20 46 69 6c 65 46 69 78 20 50 72 6f 66 65 73 73 69 6f 6e 61 6c 20 32 30 30 39 20 74 6f 20 72 65 70 61 69 72 20 61 6c 6c 20 63 6f 72 72 75 70 74 65 64 20 66 69 6c 65 73 2e 20 43 6c 69 63 6b 20 68 65 72 65 20 74 6f 20 6f 70 65 6e 20 42 75 79 20 6e 6f 77 20 70 61 67 65 2e } //1 Please, register your copy of FileFix Professional 2009 to repair all corrupted files. Click here to open Buy now page.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}