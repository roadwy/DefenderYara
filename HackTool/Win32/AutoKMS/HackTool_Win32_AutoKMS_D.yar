
rule HackTool_Win32_AutoKMS_D{
	meta:
		description = "HackTool:Win32/AutoKMS.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 53 70 70 45 78 74 43 6f 6d 4f 62 6a 48 6f 6f 6b 5c 53 70 70 45 78 74 43 6f 6d 4f 62 6a 48 6f 6f 6b 5c 62 69 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 70 70 45 78 74 43 6f 6d 4f 62 6a 48 6f 6f 6b 2e 70 64 62 } //1 Visual Studio\SppExtComObjHook\SppExtComObjHook\bin\x64\Release\SppExtComObjHook.pdb
		$a_01_1 = {49 6e 69 74 48 6f 6f 6b 40 40 59 41 58 58 5a } //1 InitHook@@YAXXZ
		$a_01_2 = {5b 00 53 00 70 00 70 00 45 00 78 00 74 00 43 00 6f 00 6d 00 4f 00 62 00 6a 00 20 00 48 00 6f 00 6f 00 6b 00 20 00 42 00 5d 00 20 00 48 00 6f 00 6f 00 6b 00 69 00 6e 00 67 00 20 00 53 00 75 00 63 00 63 00 65 00 73 00 73 00 } //1 [SppExtComObj Hook B] Hooking Success
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule HackTool_Win32_AutoKMS_D_2{
	meta:
		description = "HackTool:Win32/AutoKMS.D,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 38 35 2e 31 32 35 2e 32 33 30 2e 32 31 30 2f 4b 4d 53 70 69 63 6f 2d 73 65 74 75 70 2e 65 78 65 } //1 185.125.230.210/KMSpico-setup.exe
		$a_01_1 = {53 65 74 75 70 3d 4b 4d 53 70 69 63 6f 2d 73 65 74 75 70 2e 65 78 65 } //1 Setup=KMSpico-setup.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}