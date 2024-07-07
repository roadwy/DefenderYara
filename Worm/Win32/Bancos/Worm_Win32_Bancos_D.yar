
rule Worm_Win32_Bancos_D{
	meta:
		description = "Worm:Win32/Bancos.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 61 6e 63 61 6e 65 74 20 45 6d 70 72 65 73 61 72 69 61 6c 20 2d 20 57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 } //2 Bancanet Empresarial - Windows Interne
		$a_00_1 = {43 3a 5c 6d 6f 72 70 68 65 75 73 20 06 08 43 3a 5c 6c 69 6d 65 20 06 08 43 3a 5c 62 65 61 72 } //2
		$a_02_2 = {6d 69 63 72 6f 73 6f 66 74 61 6e 74 69 2e 65 78 65 90 02 0c 6d 72 74 2e 65 78 65 90 00 } //2
		$a_01_3 = {47 65 6e 65 72 65 20 75 6e 20 6e 75 65 76 6f 20 43 6f 64 69 67 6f 20 65 6e 20 73 75 20 44 69 73 70 6f 73 69 74 69 76 6f 20 64 65 20 41 63 63 65 73 6f 20 53 65 67 75 72 6f } //2 Genere un nuevo Codigo en su Dispositivo de Acceso Seguro
		$a_01_4 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4d 6f 72 65 53 74 75 66 5f 32 72 65 6c 7a 7a 7a 73 61 64 76 6e 71 31 32 33 34 77 33 6e 65 72 61 73 64 66 } //1 boundary="=_MoreStuf_2relzzzsadvnq1234w3nerasdf
		$a_01_5 = {43 3a 5c 41 72 63 68 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 5c 4c 61 76 61 73 6f 66 74 } //1 C:\Archivos de programa\Lavasoft
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}