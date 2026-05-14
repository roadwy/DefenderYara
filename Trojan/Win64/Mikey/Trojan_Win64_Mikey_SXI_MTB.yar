
rule Trojan_Win64_Mikey_SXI_MTB{
	meta:
		description = "Trojan:Win64/Mikey.SXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 6c 6f 61 64 65 72 20 68 61 73 20 62 65 65 6e 20 64 69 73 61 62 6c 65 64 20 62 79 20 61 64 6d 69 6e } //10 This loader has been disabled by admin
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6f 62 73 69 64 69 61 6e 5f 73 65 72 76 69 63 65 73 2e 65 78 65 20 3e 6e 75 6c 20 32 3e } //10 taskkill /f /im obsidian_services.exe >nul 2>
		$a_01_2 = {76 65 72 73 65 74 77 65 61 6b 73 5f 75 70 64 61 74 65 2e 62 61 74 } //5 versetweaks_update.bat
		$a_01_3 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 28 74 69 6d 65 6f 75 74 20 2f 74 20 32 20 2f 6e 6f 62 72 65 61 6b 20 3e 6e 75 6c } //5 if exist "%s" (timeout /t 2 /nobreak >nul
		$a_01_4 = {65 76 65 6e 74 3d 72 65 5f 74 6f 6f 6c 73 5f 74 65 72 6d 69 6e 61 74 65 64 } //5 event=re_tools_terminated
		$a_01_5 = {61 70 69 2e 6f 62 73 69 64 69 61 6e 6f 70 74 69 6d 7a 65 72 2e 63 6f 6d } //2 api.obsidianoptimzer.com
		$a_01_6 = {4f 62 73 69 64 69 61 6e 55 70 64 61 74 65 72 2f 31 2e 30 } //2 ObsidianUpdater/1.0
		$a_01_7 = {67 75 69 5c 62 69 6e 5c 61 76 61 74 61 72 5f 25 73 2e 70 6e 67 } //1 gui\bin\avatar_%s.png
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1) >=40
 
}