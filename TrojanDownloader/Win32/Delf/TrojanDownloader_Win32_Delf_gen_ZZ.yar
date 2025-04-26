
rule TrojanDownloader_Win32_Delf_gen_ZZ{
	meta:
		description = "TrojanDownloader:Win32/Delf.gen!ZZ,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 20 66 69 6c 65 7a 3a 20 70 6f 72 61 20 6b 61 63 68 61 74 6a 20 66 69 6c 65 20 23 } //1 down filez: pora kachatj file #
		$a_01_1 = {64 6f 77 6e 20 63 6f 6e 66 3a 20 70 6f 72 61 20 6b 61 63 68 61 74 6a 21 } //1 down conf: pora kachatj!
		$a_01_2 = {64 63 6f 6e 66 2e 69 6e 66 6f 2f 68 6b 2f 67 65 74 63 32 2e 70 68 70 } //1 dconf.info/hk/getc2.php
		$a_01_3 = {64 6f 77 6e 20 63 6f 6e 66 3a 20 76 72 6f 64 65 20 6f 6b 20 3d } //1 down conf: vrode ok =
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
		$a_01_5 = {6b 7a 6c 77 36 32 35 } //1 kzlw625
		$a_01_6 = {68 6b 31 2e 30 2e 30 2e 31 } //1 hk1.0.0.1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}