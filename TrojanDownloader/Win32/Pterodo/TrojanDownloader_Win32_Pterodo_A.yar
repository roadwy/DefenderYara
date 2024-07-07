
rule TrojanDownloader_Win32_Pterodo_A{
	meta:
		description = "TrojanDownloader:Win32/Pterodo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 48 14 fd 43 03 00 81 c1 c3 9e 26 00 89 48 14 c1 e9 10 81 e1 ff 7f 00 00 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 64 6f 62 65 2e 75 70 64 61 74 65 2d 73 65 72 76 69 63 65 2e 6e 65 74 2f 69 6e 64 65 78 2e 70 68 70 3f 63 6f 6d 70 3d } //1 http://adobe.update-service.net/index.php?comp=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}