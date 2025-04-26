
rule TrojanDownloader_Win32_Banload_BGI{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 47 62 50 6c 75 67 69 6e } //1 C:\Program Files\GbPlugin
		$a_01_1 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 70 61 64 } //1 C:\Arquivos de programas\Scpad
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 54 72 75 73 74 65 65 72 } //1 C:\Program Files (x86)\Trusteer
		$a_03_3 = {62 72 61 73 69 6c [0-10] 70 6f 72 74 75 67 75 ea 73 } //1
		$a_03_4 = {7e 02 33 db 8b 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7f 14 8b 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}