
rule TrojanDropper_Win32_Idicaf_C{
	meta:
		description = "TrojanDropper:Win32/Idicaf.C,SIGNATURE_TYPE_PEHSTR,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 25 25 30 } //1 del %%0
		$a_01_1 = {63 6f 6e 69 6d 65 2e 65 78 65 } //1 conime.exe
		$a_01_2 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 \svchost.exe
		$a_01_3 = {25 73 5c 25 64 5f 63 72 65 61 74 65 } //1 %s\%d_create
		$a_01_4 = {61 74 74 72 69 62 20 2d 61 20 2d 72 20 2d 73 20 2d 68 20 22 25 73 22 } //1 attrib -a -r -s -h "%s"
		$a_01_5 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 73 65 6c 66 6b 69 6c 6c } //1 if exist "%s" goto selfkill
		$a_01_6 = {25 73 5c 25 64 5f 73 65 6c 66 64 65 6c 2e 62 61 74 } //1 %s\%d_selfdel.bat
		$a_01_7 = {25 73 5c 25 64 5f 69 6e 73 74 61 6c 6c 2e 62 61 74 } //1 %s\%d_install.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}