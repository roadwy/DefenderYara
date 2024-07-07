
rule TrojanClicker_Win32_Delf_W{
	meta:
		description = "TrojanClicker:Win32/Delf.W,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 2e 32 33 34 2e 32 37 2e 31 34 36 2f 70 6f 70 75 70 2e 64 6f } //1 http://1.234.27.146/popup.do
		$a_01_1 = {63 6d 64 3d 72 65 64 69 72 65 63 74 5f 6c 69 73 74 } //1 cmd=redirect_list
		$a_01_2 = {63 6d 64 3d 72 65 64 69 72 65 63 74 5f 6c 6f 67 26 75 72 6c 3d } //1 cmd=redirect_log&url=
		$a_01_3 = {63 6d 64 3d 6b 65 79 77 6f 72 64 4c 6f 67 26 6b 65 79 77 6f 72 64 3d } //1 cmd=keywordLog&keyword=
		$a_01_4 = {63 6d 64 3d 70 6f 70 75 70 4c 6f 67 26 6b 65 79 77 6f 72 64 3d } //1 cmd=popupLog&keyword=
		$a_01_5 = {63 6d 64 3d 67 65 74 53 69 74 65 26 6b 65 79 77 6f 72 64 3d } //1 cmd=getSite&keyword=
		$a_01_6 = {57 49 4e 44 4f 57 53 2f 73 79 73 74 65 6d 33 32 2f 70 6f 67 2e 6c 6f 67 } //1 WINDOWS/system32/pog.log
		$a_01_7 = {57 49 4e 44 4f 57 53 2f 73 79 73 74 65 6d 33 32 2f 63 66 66 6d 6f 6d 2e 6c 6f 67 } //1 WINDOWS/system32/cffmom.log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}