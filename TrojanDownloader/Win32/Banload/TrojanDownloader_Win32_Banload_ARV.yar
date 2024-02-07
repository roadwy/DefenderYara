
rule TrojanDownloader_Win32_Banload_ARV{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARV,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 47 62 50 6c 75 67 69 6e 5c 62 62 2e 67 70 63 } //02 00  C:\Program Files (x86)\GbPlugin\bb.gpc
		$a_01_1 = {43 49 43 4c 53 2e 64 } //02 00  CICLS.d
		$a_01_2 = {47 61 72 61 6e 74 69 72 44 4c 4c } //03 00  GarantirDLL
		$a_01_3 = {49 6e 66 6f 72 49 6e 66 65 63 } //05 00  InforInfec
		$a_01_4 = {50 72 6f 76 69 64 65 72 3d 53 51 4c 4f 4c 45 44 42 2e 31 3b 50 61 73 73 77 6f 72 64 3d 6d 61 73 74 65 72 31 39 37 37 38 32 31 32 3b 50 65 72 73 69 73 74 20 53 65 63 75 72 69 74 79 20 49 6e 66 6f 3d 54 72 75 65 3b 55 73 65 72 20 49 44 3d 6c 6f 67 63 6f 6e 74 61 67 65 6d 3b 49 6e 69 74 69 61 6c 20 43 61 74 61 6c 6f 67 3d 63 6f 6e 74 61 67 65 6d 3b 44 61 74 61 20 53 6f 75 72 63 } //00 00  Provider=SQLOLEDB.1;Password=master19778212;Persist Security Info=True;User ID=logcontagem;Initial Catalog=contagem;Data Sourc
		$a_00_5 = {5d 04 00 00 05 fe } //02 80 
	condition:
		any of ($a_*)
 
}