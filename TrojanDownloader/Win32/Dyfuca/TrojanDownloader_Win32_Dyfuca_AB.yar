
rule TrojanDownloader_Win32_Dyfuca_AB{
	meta:
		description = "TrojanDownloader:Win32/Dyfuca.AB,SIGNATURE_TYPE_PEHSTR,fffffffa 00 fffffffa 00 09 00 00 64 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 6e 74 65 72 6e 65 74 2d 6f 70 74 69 6d 69 7a 65 72 2e 63 6f 6d 2f 63 6f 6e 66 2f 78 6d 6c 2f } //64 00  http://www.internet-optimizer.com/conf/xml/
		$a_01_1 = {68 74 74 70 3a 2f 2f 63 64 6e 2e 6d 6f 76 69 65 73 2d 65 74 63 2e 63 6f 6d 2f 69 6f 2f 6c 65 67 61 6c 2f 45 55 4c 41 2f 45 55 4c 41 2e 63 74 78 74 } //19 00  http://cdn.movies-etc.com/io/legal/EULA/EULA.ctxt
		$a_01_2 = {43 3a 5c 49 6e 74 65 72 6e 65 74 20 4f 70 74 69 6d 69 7a 65 72 } //19 00  C:\Internet Optimizer
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 4f 70 74 69 6d 69 7a 65 72 } //19 00  C:\Program Files\Internet Optimizer
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 79 46 75 43 41 } //19 00  C:\Program Files\DyFuCA
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 41 76 65 6e 75 65 20 4d 65 64 69 61 5c 49 6e 74 65 72 6e 65 74 20 4f 70 74 69 6d 69 7a 65 72 } //19 00  Software\Avenue Media\Internet Optimizer
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 4d 65 4f 70 74 } //19 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AMeOpt
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 41 76 65 6e 75 65 20 4d 65 64 69 61 } //19 00  SOFTWARE\Policies\Avenue Media
		$a_01_8 = {76 65 72 3d 25 73 26 72 69 64 3d 25 73 26 63 6c 73 3d 25 73 } //00 00  ver=%s&rid=%s&cls=%s
	condition:
		any of ($a_*)
 
}