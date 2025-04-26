
rule TrojanDownloader_Win32_Toselos_A{
	meta:
		description = "TrojanDownloader:Win32/Toselos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 58 6a 04 8b 45 fc e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 0c } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 2f 74 6f 6f 6c 73 2e 74 78 74 } //1 http://%s/tools.txt
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 50 49 44 20 25 64 } //1 taskkill /F /PID %d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}