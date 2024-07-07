
rule TrojanSpy_Win32_Roscamoin_A{
	meta:
		description = "TrojanSpy:Win32/Roscamoin.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {77 2e 72 73 63 61 6d 6e 6c 2e 63 6f 6d 2f 64 2f 67 65 74 5f 6b 65 79 73 2e 70 68 70 3f 6b 65 79 73 5f 70 72 65 73 73 65 64 3d } //4 w.rscamnl.com/d/get_keys.php?keys_pressed=
		$a_01_1 = {5c 00 67 00 6f 00 6f 00 64 00 20 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 } //4 \good keylogger\
		$a_01_2 = {31 00 39 00 38 00 2e 00 31 00 37 00 33 00 2e 00 31 00 32 00 34 00 2e 00 31 00 30 00 37 00 2f 00 64 00 2f 00 67 00 65 00 74 00 5f 00 6b 00 65 00 79 00 73 00 2e 00 70 00 68 00 70 00 } //4 198.173.124.107/d/get_keys.php
		$a_01_3 = {6b 00 65 00 79 00 73 00 5f 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 3d 00 } //2 keys_pressed=
		$a_01_4 = {49 6e 73 74 61 6c 6c 5f 66 6c 61 73 68 5f 70 6c 61 79 65 72 } //1 Install_flash_player
		$a_01_5 = {52 65 71 75 69 72 65 64 20 4b 65 79 20 53 74 72 6f 6b 65 73 20 3a } //1 Required Key Strokes :
		$a_01_6 = {56 69 63 74 69 6d 20 4e 61 6d 65 20 3a } //1 Victim Name :
		$a_01_7 = {67 65 74 5f 64 69 72 5f 6c 69 73 74 5f 77 69 6e 37 } //1 get_dir_list_win7
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}