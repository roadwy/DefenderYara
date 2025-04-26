
rule TrojanDownloader_O97M_Obfuse_HPU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HPU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 65 69 6e 6b 6f 6e 68 75 6e 2e 45 58 45 43 20 6c 69 73 74 65 6e 31 20 2b 20 6d 61 64 61 72 32 20 2b 20 6a 61 6e 75 33 20 2b 20 66 61 6b 69 72 34 } //1 meinkonhun.EXEC listen1 + madar2 + janu3 + fakir4
		$a_03_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 22 20 2b 20 49 6e 74 32 53 74 72 28 22 [0-0a] 22 29 20 2b 20 49 6e 74 32 53 74 72 28 22 } //1
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 20 41 73 20 53 74 72 69 6e 67 } //1 Function Auto_Close() As String
		$a_00_3 = {47 6f 54 6f 20 79 79 78 43 5a 67 6e 52 66 65 75 78 41 } //1 GoTo yyxCZgnRfeuxA
		$a_00_4 = {4b 6e 44 56 71 4a 44 74 5a 69 69 68 6d 51 50 51 42 4f 3a } //1 KnDVqJDtZiihmQPQBO:
		$a_00_5 = {73 4e 61 6d 65 20 3d 20 4d 69 64 28 73 54 65 78 74 2c 20 49 2c 20 33 29 } //1 sName = Mid(sText, I, 3)
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}