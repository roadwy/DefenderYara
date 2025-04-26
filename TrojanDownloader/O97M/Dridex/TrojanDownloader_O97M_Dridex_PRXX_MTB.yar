
rule TrojanDownloader_O97M_Dridex_PRXX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PRXX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4d 69 64 28 22 38 74 39 24 5e 3d 30 6d 3a 62 50 47 68 74 74 70 73 3a 2f 2f 66 69 74 7a 67 65 72 61 6c 64 73 74 72 65 65 74 2e 63 6f 6d 2f 61 70 2d 70 68 6f 74 6f 73 2f 74 68 65 6d 65 73 2f 6d 6f 64 75 73 2f 63 73 73 2f 66 6f 6e 74 65 6c 6c 6f 2f 31 6a 35 79 5a 4c 53 69 34 56 45 2e 70 68 70 2f 2d 2d 74 33 68 71 68 4d 75 67 6a 75 64 6c 22 } //1 = Mid("8t9$^=0m:bPGhttps://fitzgeraldstreet.com/ap-photos/themes/modus/css/fontello/1j5yZLSi4VE.php/--t3hqhMugjudl"
		$a_01_1 = {3d 20 4d 69 64 28 22 43 43 35 61 4a 38 47 34 44 71 6f 68 74 74 70 73 3a 2f 2f 61 68 64 6d 73 70 6f 72 74 2e 63 6f 6d 2f 62 6f 6f 74 73 74 72 61 70 2f 73 63 72 69 70 74 73 2f 5f 6e 6f 74 65 73 2f 58 77 69 34 4b 30 42 72 6d 77 58 36 68 66 2e 70 68 70 32 44 38 42 2e 69 64 57 64 44 22 2c } //1 = Mid("CC5aJ8G4Dqohttps://ahdmsport.com/bootstrap/scripts/_notes/Xwi4K0BrmwX6hf.php2D8B.idWdD",
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 74 65 73 74 65 2e 73 69 74 69 6f 64 6f 61 73 74 72 6f 6e 61 75 74 61 2e 63 6f 6d 2e 62 72 2f 3e 33 33 5e 76 6a 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 73 2f 74 69 6e 79 6d 63 65 2f 70 6c 3e 33 33 5e 76 6a 75 67 3e 33 33 5e 76 6a 69 6e 73 2f 63 68 61 72 3e 33 33 5e 76 6a 6d 61 70 2f 4d 31 39 6a 6f 6f 50 72 69 38 54 3e 33 33 5e 76 6a 71 2e 70 68 70 22 2c } //1 = Replace("https://teste.sitiodoastronauta.com.br/>33^vjwp-includes/js/tinymce/pl>33^vjug>33^vjins/char>33^vjmap/M19jooPri8T>33^vjq.php",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}