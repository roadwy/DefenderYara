
rule TrojanDownloader_Win32_Bancos_GH{
	meta:
		description = "TrojanDownloader:Win32/Bancos.GH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 54 72 69 78 4e 65 74 43 6c 61 73 73 45 78 44 57 00 } //01 00  吀楲乸瑥汃獡䕳䑸W
		$a_01_1 = {5c 50 72 6f 6a 65 74 6f 73 5c 42 6f 74 6e 65 74 73 5c 54 72 69 78 4e 65 74 5c 73 6f 75 72 63 65 5c 54 72 69 78 4e 65 74 5c 52 65 6c 65 61 73 65 5c 46 6c 61 73 68 20 44 6f 77 6e 6c 6f 61 64 65 72 2e 70 64 62 } //00 00  \Projetos\Botnets\TrixNet\source\TrixNet\Release\Flash Downloader.pdb
	condition:
		any of ($a_*)
 
}