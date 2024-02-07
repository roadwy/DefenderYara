
rule TrojanDownloader_O97M_Powdow_RST_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RST!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 68 65 6c 6c 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  shell = VBA.CreateObject("WScript.Shell")
		$a_00_1 = {73 68 65 6c 6c 2e 52 75 6e 28 22 50 6f 77 65 72 73 68 65 6c 6c 20 49 60 45 58 20 28 28 6e 60 65 60 57 60 2d 4f 62 6a 60 45 60 63 60 54 20 28 28 27 4e 65 74 27 2b 27 2e 27 2b 27 57 65 62 63 27 2b 27 6c 69 65 6e 74 27 } //01 00  shell.Run("Powershell I`EX ((n`e`W`-Obj`E`c`T (('Net'+'.'+'Webc'+'lient'
		$a_00_2 = {44 27 2b 27 6f 27 2b 27 77 27 2b 27 6e 27 2b 27 6c 27 2b 27 6f 27 2b 27 61 27 2b 27 64 27 2b 27 73 27 2b 27 74 72 69 27 2b 27 27 2b 27 27 2b 27 27 2b 27 27 2b 27 27 2b 27 27 2b 27 } //01 00  D'+'o'+'w'+'n'+'l'+'o'+'a'+'d'+'s'+'tri'+''+''+''+''+''+''+'
		$a_00_3 = {2b 27 27 2b 27 6e 27 2b 27 67 27 29 29 2e 49 6e 56 6f 6b 45 28 28 28 27 6b 69 6e 6b 27 29 29 29 29 22 2c 20 30 2c 20 46 61 6c 73 65 } //01 00  +''+'n'+'g')).InVokE((('kink'))))", 0, False
		$a_00_4 = {41 75 74 6f 5f 4f 70 65 6e 28 29 } //00 00  Auto_Open()
	condition:
		any of ($a_*)
 
}