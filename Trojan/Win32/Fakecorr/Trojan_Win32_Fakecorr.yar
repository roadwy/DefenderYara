
rule Trojan_Win32_Fakecorr{
	meta:
		description = "Trojan:Win32/Fakecorr,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 90 09 11 00 66 81 90 01 01 4d 5a 75 90 01 01 8b 90 01 01 3c 03 90 01 01 89 90 00 } //5
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 4f 57 5c 6b 65 79 62 6f 61 72 64 } //2 SOFTWARE\Microsoft\Windows NT\CurrentVersion\WOW\keyboard
		$a_02_2 = {63 77 6d 75 90 02 04 63 77 63 5f 63 6c 61 73 73 90 00 } //2
		$a_00_3 = {70 75 62 6c 69 63 2f 73 74 61 74 2e 70 68 70 3f 63 6d 64 3d } //2 public/stat.php?cmd=
		$a_00_4 = {43 6f 72 72 75 70 74 65 64 20 62 6c 6f 63 6b 3a } //1 Corrupted block:
		$a_00_5 = {69 6e 73 74 61 6c 6c 20 72 65 63 6f 6d 6d 65 6e 64 65 64 20 66 69 6c 65 20 72 65 70 61 69 72 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e } //1 install recommended file repair application.
		$a_00_6 = {74 6f 20 72 65 70 61 69 72 20 61 6c 6c 20 63 6f 72 72 75 70 74 65 64 20 66 69 6c 65 73 2e } //1 to repair all corrupted files.
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=13
 
}