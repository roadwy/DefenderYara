
rule TrojanDownloader_Win32_Small_WY{
	meta:
		description = "TrojanDownloader:Win32/Small.WY,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 72 61 72 5f 63 6f 6e 66 69 67 2e 74 6d 70 } //2 winrar_config.tmp
		$a_01_1 = {68 74 74 70 3a 2f 2f 6b 70 2e 39 } //3 http://kp.9
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 46 72 65 65 52 61 70 69 64 5c 34 2e 62 61 74 } //2 C:\Program Files\FreeRapid\4.bat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=7
 
}