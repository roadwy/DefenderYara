
rule TrojanSpy_Win32_Bancos_XR{
	meta:
		description = "TrojanSpy:Win32/Bancos.XR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 66 75 74 77 54 5c 74 66 6a 64 6a 6d 70 51 5c 6f 70 6a 74 73 66 58 75 6f 66 73 73 76 44 5c 74 61 70 65 6f 6a 41 5c 75 67 70 74 70 73 64 6a 4e 5c 66 73 62 61 75 67 70 54 5c } //4 nfutwT\tfjdjmpQ\opjtsfXuofssvD\tapeojA\ugptpsdjN\fsbaugpT\
		$a_01_1 = {4f 56 53 5c 4f 50 4a 54 53 46 58 55 4f 46 53 53 56 44 5c 54 41 50 45 4f 4a 41 5c 55 47 50 54 50 53 44 4a 4e 5c 46 53 42 41 55 47 50 54 } //3 OVS\OPJTSFXUOFSSVD\TAPEOJA\UGPTPSDJN\FSBAUGPT
		$a_01_2 = {45 64 69 74 53 65 6e 43 61 72 64 } //2 EditSenCard
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=9
 
}