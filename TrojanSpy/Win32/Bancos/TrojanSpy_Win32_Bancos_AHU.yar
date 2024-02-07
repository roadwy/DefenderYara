
rule TrojanSpy_Win32_Bancos_AHU{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHU,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3b 50 61 73 73 77 6f 72 64 3d 32 6e 31 61 63 37 34 61 3b 50 65 72 73 69 73 74 20 53 65 63 75 72 69 74 79 20 49 6e 66 6f 3d 54 72 75 65 3b 55 73 65 72 20 49 44 3d 73 71 6c 75 73 65 72 3b 49 6e 69 74 69 61 6c 20 43 61 74 61 6c 6f 67 3d 73 71 6c 64 61 74 61 62 61 73 65 3b 44 61 74 61 20 53 6f 75 72 63 65 3d 73 71 6c 32 30 30 31 2e 73 68 61 72 65 64 2d 73 65 72 76 65 72 73 2e 63 6f 6d 2c 31 30 38 36 } //01 00  ;Password=2n1ac74a;Persist Security Info=True;User ID=sqluser;Initial Catalog=sqldatabase;Data Source=sql2001.shared-servers.com,1086
		$a_01_1 = {28 00 22 00 49 00 44 00 5f 00 50 00 43 00 22 00 2c 00 20 00 22 00 4e 00 4d 00 46 00 55 00 4e 00 43 00 49 00 4f 00 4e 00 41 00 52 00 49 00 4f 00 22 00 2c 00 20 00 22 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 43 00 41 00 4f 00 22 00 29 00 } //01 00  ("ID_PC", "NMFUNCIONARIO", "INFORMACAO")
		$a_01_2 = {44 00 4f 00 43 00 55 00 4d 00 45 00 4e 00 54 00 4f 00 53 00 2e 00 65 00 78 00 65 00 } //00 00  DOCUMENTOS.exe
	condition:
		any of ($a_*)
 
}