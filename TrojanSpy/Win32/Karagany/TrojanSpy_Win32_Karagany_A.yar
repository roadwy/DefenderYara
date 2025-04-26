
rule TrojanSpy_Win32_Karagany_A{
	meta:
		description = "TrojanSpy:Win32/Karagany.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 3a 5c 66 6c 61 73 68 5c 6f 74 68 65 72 5c 43 2b 2b 5c 4c 69 74 65 4c 6f 61 64 65 72 20 31 2e 31 5c 52 65 6c 65 61 73 65 5c 6b 65 79 6c 6f 67 2e 70 64 62 } //2 M:\flash\other\C++\LiteLoader 1.1\Release\keylog.pdb
		$a_01_1 = {4b 65 79 6c 6f 67 48 65 6c 70 65 72 54 68 72 65 61 64 3a 20 53 74 6f 70 20 4b 65 79 6c 6f 67 } //1 KeylogHelperThread: Stop Keylog
		$a_01_2 = {5b 4c 43 54 52 4c 5d 00 5b 52 43 54 52 4c 5d 00 5b 49 4e 53 45 52 54 5d } //1 䱛呃䱒]剛呃䱒]䥛华剅嵔
		$a_01_3 = {43 3a 5c 25 41 50 50 44 41 54 41 25 5c 53 71 6c 5c 6b 6c 6f 67 2e 64 62 63 } //1 C:\%APPDATA%\Sql\klog.dbc
		$a_01_4 = {4d 65 6d 62 65 72 20 57 69 6e 64 6f 77 } //1 Member Window
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}