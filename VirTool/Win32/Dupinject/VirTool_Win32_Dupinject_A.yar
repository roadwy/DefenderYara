
rule VirTool_Win32_Dupinject_A{
	meta:
		description = "VirTool:Win32/Dupinject.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2f 66 } //1 taskkill /im explorer.exe /f
		$a_01_1 = {43 4c 53 49 44 5c 7b 33 35 43 45 43 38 41 33 2d 32 42 45 36 2d 31 31 44 32 2d 38 37 37 33 2d 39 32 45 32 32 30 35 32 34 31 35 33 7d 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 CLSID\{35CEC8A3-2BE6-11D2-8773-92E220524153}\InProcServer32
		$a_03_2 = {6a 00 6a 20 6a 01 6a 00 6a 03 68 00 00 00 c0 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}