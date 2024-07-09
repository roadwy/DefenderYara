
rule TrojanDownloader_O97M_Donoff_FA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 62 5e 69 5e 74 5e 73 5e 61 5e 64 5e 6d 69 6e 5e 20 2f 74 5e 72 61 5e 6e 5e 73 5e 66 5e 65 5e 72 5e 20 5e 2f 5e 64 5e 6f 5e 77 5e 6e 5e 6c 5e 6f 5e 61 5e 64 } //1 cmd.exe /c b^i^t^s^a^d^min^ /t^ra^n^s^f^e^r^ ^/^d^o^w^n^l^o^a^d
		$a_00_1 = {25 74 6d 70 25 2f 44 53 61 6a 49 4f 44 41 2e 65 78 65 } //1 %tmp%/DSajIODA.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_FA_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 46 69 6c 65 6f 75 74 20 3d 20 46 53 4f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 45 6e 76 69 72 6f 6e 28 22 41 70 70 64 61 74 61 22 29 20 26 20 22 5c 67 74 6c 73 2e 76 62 73 22 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //1 Set Fileout = FSO.CreateTextFile(Environ("Appdata") & "\gtls.vbs", True, True)
		$a_00_1 = {46 69 6c 65 6f 75 74 2e 57 72 69 74 65 20 55 73 65 72 46 6f 72 6d 31 2e 74 78 74 56 42 53 2e 54 65 78 74 } //1 Fileout.Write UserForm1.txtVBS.Text
		$a_02_2 = {53 65 74 41 74 74 72 20 [0-10] 2c 20 76 62 48 69 64 64 65 6e } //1
		$a_00_3 = {77 73 68 53 68 65 6c 6c 2e 52 75 6e 20 66 70 } //1 wshShell.Run fp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_FA_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 46 6f 6c 64 65 72 20 3d 20 57 73 68 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 27 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 27 29 2b 27 5c 5c 50 79 74 68 6f 6e 27 3b } //1 pFolder = WshShell.ExpandEnvironmentStrings('%localappdata%')+'\\Python';
		$a_01_1 = {67 65 74 5f 70 61 67 65 5f 63 6f 6e 74 65 6e 74 5f 77 69 74 68 5f 69 65 28 73 65 72 76 65 72 20 2b 20 27 2f 67 65 74 69 64 27 2c 20 27 61 63 74 69 6f 6e 3d 75 70 26 75 69 64 3d 27 2b 69 64 2b 27 26 61 6e 74 69 76 69 72 75 73 3d 27 2b 72 65 74 75 72 6e 5f 61 76 5f 6e 61 6d 65 28 29 29 3b } //1 get_page_content_with_ie(server + '/getid', 'action=up&uid='+id+'&antivirus='+return_av_name());
		$a_01_2 = {79 6f 75 77 69 6c 6c 6e 6f 74 66 69 6e 64 74 68 69 73 61 6e 79 77 68 61 72 65 } //1 youwillnotfindthisanywhare
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}