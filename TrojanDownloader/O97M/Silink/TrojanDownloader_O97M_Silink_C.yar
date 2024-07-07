
rule TrojanDownloader_O97M_Silink_C{
	meta:
		description = "TrojanDownloader:O97M/Silink.C,SIGNATURE_TYPE_MACROHSTR_EXT,2b 00 2b 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6c 77 61 72 65 } //20 malware
		$a_01_1 = {6d 62 61 6d 2e 65 78 65 } //12 mbam.exe
		$a_01_2 = {57 69 6e 44 65 66 65 6e 64 } //12 WinDefend
		$a_01_3 = {4d 63 53 68 69 65 6c 64 2e 65 78 65 } //12 McShield.exe
		$a_01_4 = {6d 73 68 74 61 2e 65 78 65 20 68 74 74 70 } //10 mshta.exe http
		$a_01_5 = {53 68 65 6c 6c 20 28 22 63 6d 64 2e 65 78 65 20 2f 63 } //1 Shell ("cmd.exe /c
		$a_01_6 = {77 53 68 65 6c 6c 2e 72 75 6e 28 22 22 63 6d 64 2e 65 78 65 20 2f 63 } //1 wShell.run(""cmd.exe /c
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*12+(#a_01_2  & 1)*12+(#a_01_3  & 1)*12+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=43
 
}