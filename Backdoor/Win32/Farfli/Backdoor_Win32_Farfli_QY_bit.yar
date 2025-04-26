
rule Backdoor_Win32_Farfli_QY_bit{
	meta:
		description = "Backdoor:Win32/Farfli.QY!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4b 53 61 66 65 54 72 61 79 2e 65 78 65 } //1 KSafeTray.exe
		$a_00_1 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_00_2 = {2f 63 20 64 65 6c 20 2f 71 20 25 73 } //1 /c del /q %s
		$a_00_3 = {00 4c 6f 6e 67 5a 75 6f 6d 73 00 } //1
		$a_01_4 = {49 6e 6a 65 63 74 44 4c 4c 2e 64 6c 6c } //1 InjectDLL.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}