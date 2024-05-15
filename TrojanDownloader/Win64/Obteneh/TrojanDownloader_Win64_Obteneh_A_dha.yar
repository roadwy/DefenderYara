
rule TrojanDownloader_Win64_Obteneh_A_dha{
	meta:
		description = "TrojanDownloader:Win64/Obteneh.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 70 72 69 6d 65 72 5f 70 61 73 6f } //01 00  main.primer_paso
		$a_01_1 = {6d 61 69 6e 2e 75 6e 5f 7a 69 70 } //01 00  main.un_zip
		$a_01_2 = {6d 61 69 6e 2e 70 72 6f 63 65 73 61 72 } //01 00  main.procesar
		$a_01_3 = {6d 61 69 6e 2e 6d 6f 73 74 72 61 72 5f 70 72 6f 67 72 65 73 6f } //01 00  main.mostrar_progreso
		$a_01_4 = {6d 61 69 6e 2e 6f 62 74 65 6e 65 72 5f 7a 69 70 2e 66 75 6e 63 31 } //01 00  main.obtener_zip.func1
		$a_01_5 = {43 3a 2f 77 69 6e 64 6f 77 73 5f 75 70 64 61 74 65 2f 6d 61 69 6e 2e 67 6f } //00 00  C:/windows_update/main.go
	condition:
		any of ($a_*)
 
}