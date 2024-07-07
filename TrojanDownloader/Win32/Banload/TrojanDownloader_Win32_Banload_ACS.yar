
rule TrojanDownloader_Win32_Banload_ACS{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACS,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 45 fa 02 c3 88 45 fb 8d 85 ec fe ff ff 8b 55 fc 8a 54 1a ff 32 55 fb } //10
		$a_01_1 = {4c 61 62 65 6c 5f 41 72 71 75 69 76 6f 73 } //1 Label_Arquivos
		$a_01_2 = {56 65 72 69 66 69 63 61 45 6d 70 72 65 73 61 } //1 VerificaEmpresa
		$a_01_3 = {42 61 69 78 61 4d 75 73 69 63 45 6e 64 } //1 BaixaMusicEnd
		$a_01_4 = {54 65 6d 70 44 69 6e 61 6d 69 63 6f 45 6e 64 } //1 TempDinamicoEnd
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}