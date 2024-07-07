
rule TrojanSpy_Win32_Bancos_ALB{
	meta:
		description = "TrojanSpy:Win32/Bancos.ALB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 76 69 64 65 72 3d 53 51 4c 4f 4c 45 44 42 2e 31 3b 50 61 73 73 77 6f 72 64 3d 32 6e 31 61 63 37 34 61 } //1 Provider=SQLOLEDB.1;Password=2n1ac74a
		$a_01_1 = {44 61 74 61 20 53 6f 75 72 63 65 3d 64 62 73 71 30 30 31 30 2e 77 68 73 65 72 76 69 64 6f 72 2e 63 6f 6d } //1 Data Source=dbsq0010.whservidor.com
		$a_01_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 49 4d 41 47 45 4d 53 20 57 48 45 52 45 20 49 44 5f 47 41 4d 45 20 3d 20 31 } //1 SELECT * FROM IMAGEMS WHERE ID_GAME = 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}