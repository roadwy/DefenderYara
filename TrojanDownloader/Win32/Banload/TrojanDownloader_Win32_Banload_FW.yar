
rule TrojanDownloader_Win32_Banload_FW{
	meta:
		description = "TrojanDownloader:Win32/Banload.FW,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {7c 5f 77 65 3d 32 33 7c 5f 66 3d 2f } //1 |_we=23|_f=/
		$a_01_1 = {2a 3a 45 6e 61 62 6c 65 64 3a 4f 75 74 6c 6f 6f 6b 73 2e 65 78 65 } //1 *:Enabled:Outlooks.exe
		$a_01_2 = {2a 3a 45 6e 61 62 6c 65 64 3a 78 63 6f 6d 2e 65 78 65 } //1 *:Enabled:xcom.exe
		$a_01_3 = {5c 6f 75 74 5c 4f 75 74 6c 6f 6f 6b 73 2e 65 78 65 } //1 \out\Outlooks.exe
		$a_01_4 = {5c 63 6f 6d 5c 77 6c 63 6f 6d 2e 65 78 65 } //1 \com\wlcom.exe
		$a_01_5 = {5c 63 6f 6d 5c 64 6f 77 6e 2e 74 78 74 } //1 \com\down.txt
		$a_01_6 = {75 72 6c 74 65 72 72 61 5f 4f 6e 43 6c 69 63 6b } //1 urlterra_OnClick
		$a_01_7 = {73 65 6e 68 61 } //1 senha
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}