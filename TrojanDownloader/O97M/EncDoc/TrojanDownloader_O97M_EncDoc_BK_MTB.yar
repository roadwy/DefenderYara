
rule TrojanDownloader_O97M_EncDoc_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 68 74 27 2b 27 74 70 3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f 77 30 79 4c 56 } //01 00  'ht'+'tp://paste.ee/r/w0yLV
		$a_01_1 = {28 6e 65 77 60 2d 4f 42 60 6a 65 43 54 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 } //01 00  (new`-OB`jeCT('Net.WebClient'))
		$a_01_2 = {2e 27 44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 } //00 00  .'DoWnloAdsTrInG'
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 75 74 65 64 69 67 69 74 61 6c 70 68 6f 74 6f 67 72 61 70 68 79 2e 63 6f 6d 2f 63 75 74 65 70 68 2f 70 68 6f 74 6f 73 6d 61 2e 70 68 70 } //01 00  https://www.cutedigitalphotography.com/cuteph/photosma.php
		$a_01_1 = {43 3a 5c 62 63 65 6f 64 } //01 00  C:\bceod
		$a_01_2 = {5c 65 77 66 76 73 2e 65 78 65 } //00 00  \ewfvs.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_BK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 45 58 20 28 6e 65 77 60 2d 4f 42 60 6a 65 43 54 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 } //01 00  IEX (new`-OB`jeCT('Net.WebClient'))
		$a_01_1 = {2e 27 44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 28 27 68 74 27 2b 27 74 70 3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f 4f 31 70 77 33 27 29 } //00 00  .'DoWnloAdsTrInG'('ht'+'tp://paste.ee/r/O1pw3')
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_BK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 28 27 68 74 74 70 73 3a 2f 2f 73 63 72 65 77 2d 6d 61 6c 77 72 68 75 6e 74 65 72 74 65 61 6d 73 2e 63 6f 6d 2f 73 63 61 6e 6d 65 2e 74 78 74 27 29 22 } //01 00  DoWnloAdsTrInG'('https://screw-malwrhunterteams.com/scanme.txt')"
		$a_01_1 = {49 45 58 20 28 6e 65 77 60 2d 4f 42 60 6a 65 43 54 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 } //01 00  IEX (new`-OB`jeCT('Net.WebClient'))
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 67 } //00 00  powershell -Command g
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_BK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 68 69 64 64 65 6e 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 } //01 00  powershell -w hidden (New-Object Net.WebClient)
		$a_00_1 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 63 72 79 70 74 6f 70 72 6f 2e 67 61 2f 46 69 6c 65 2f 61 70 6f 2e 65 78 65 27 2c 27 43 3a 5c 50 52 4f 47 52 41 4d 44 41 54 41 5c 61 79 61 74 61 67 65 2e 65 78 65 27 29 3b } //00 00  .DownloadFile('https://cryptopro.ga/File/apo.exe','C:\PROGRAMDATA\ayatage.exe');
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_BK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 28 27 68 74 74 70 73 3a 2f 2f 73 63 72 65 77 2d 6d 61 6c 77 72 68 75 6e 74 65 72 74 65 61 6d 73 2e 63 6f 6d 2f 73 63 61 6e 6d 65 2e 74 78 74 27 29 22 } //01 00  DoWnloAdsTrInG'('https://screw-malwrhunterteams.com/scanme.txt')"
		$a_01_1 = {44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 28 27 68 74 74 70 3a 2f 2f 73 6b 69 64 77 61 72 65 2d 6d 61 6c 77 72 68 75 6e 74 65 72 74 65 61 6d 73 2e 63 6f 6d 2f 73 63 61 6e 6d 65 2e 74 78 74 27 29 } //01 00  DoWnloAdsTrInG'('http://skidware-malwrhunterteams.com/scanme.txt')
		$a_01_2 = {49 45 58 20 28 6e 65 77 60 2d 4f 42 60 6a 65 43 54 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 } //01 00  IEX (new`-OB`jeCT('Net.WebClient'))
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 67 } //00 00  powershell -Command g
	condition:
		any of ($a_*)
 
}