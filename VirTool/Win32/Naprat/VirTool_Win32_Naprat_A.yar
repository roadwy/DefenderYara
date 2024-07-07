
rule VirTool_Win32_Naprat_A{
	meta:
		description = "VirTool:Win32/Naprat.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 7a 65 72 30 5c 44 65 73 6b 74 6f 70 5c 50 72 6f 6a 65 63 74 73 5c 50 61 69 4e 20 52 41 54 5c 43 6c 69 65 6e 74 } //1 C:\Documents and Settings\zer0\Desktop\Projects\PaiN RAT\Client
		$a_01_1 = {53 65 72 76 65 72 2e 65 78 65 20 2d 73 72 74 20 2d 72 65 64 20 2d 66 6f 72 63 65 20 2d 70 64 74 } //1 Server.exe -srt -red -force -pdt
		$a_01_2 = {55 73 65 20 27 25 64 65 66 61 75 6c 74 62 72 6f 77 73 65 72 25 27 20 54 6f 20 49 6e 6a 65 63 74 20 69 6e 74 6f 20 44 65 66 61 75 6c 74 20 42 72 6f 77 73 65 72 } //1 Use '%defaultbrowser%' To Inject into Default Browser
		$a_01_3 = {4b 65 79 6c 6f 67 46 69 6c 65 } //1 KeylogFile
		$a_01_4 = {50 69 6e 67 49 6e 74 65 72 76 61 6c } //1 PingInterval
		$a_01_5 = {62 74 6e 44 6f 77 6e 6c 6f 61 64 54 6f 4d 65 6d 6f 72 79 } //1 btnDownloadToMemory
		$a_01_6 = {63 62 41 6e 74 69 41 6e 75 62 69 73 53 61 6e 64 62 6f 78 } //1 cbAntiAnubisSandbox
		$a_01_7 = {63 62 41 6e 74 69 4e 6f 72 6d 61 6e 53 61 6e 64 62 6f 78 } //1 cbAntiNormanSandbox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}