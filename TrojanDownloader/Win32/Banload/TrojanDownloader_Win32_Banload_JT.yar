
rule TrojanDownloader_Win32_Banload_JT{
	meta:
		description = "TrojanDownloader:Win32/Banload.JT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 69 65 78 70 6c 6f 72 65 72 72 2e 65 78 65 } //01 00  xiexplorerr.exe
		$a_01_1 = {45 6e 76 69 61 64 6f 72 20 58 5c 4c 6f 67 61 72 20 42 42 5c 50 75 78 61 64 6f 72 20 32 5c 70 75 78 61 64 6f 72 2e 65 78 65 } //01 00  Enviador X\Logar BB\Puxador 2\puxador.exe
		$a_01_2 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 } //00 00 
	condition:
		any of ($a_*)
 
}