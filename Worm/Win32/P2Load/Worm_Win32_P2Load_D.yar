
rule Worm_Win32_P2Load_D{
	meta:
		description = "Worm:Win32/P2Load.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 6a 75 69 69 6c 6c 6f 73 6b 73 2e 73 79 74 65 73 2e 6e 65 74 2f } //1 http://juiillosks.sytes.net/
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 64 75 74 74 79 2e 64 65 2f } //1 http://www.dutty.de/
		$a_00_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4b 61 7a 61 61 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 } //1 Program Files\Kazaa\My Shared Folder
		$a_00_3 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 65 4d 75 6c 65 5c 49 6e 63 6f 6d 69 6e 67 } //1 Program Files\eMule\Incoming
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 69 4d 65 73 68 5c 69 4d 65 73 68 35 5c 54 72 61 6e 73 66 65 72 } //1 Software\iMesh\iMesh5\Transfer
		$a_02_5 = {2f 64 61 74 61 2f 66 69 6c 65 [0-05] 2e 73 79 73 } //1
		$a_00_6 = {7a 3a 5c 50 72 6f 67 72 61 6d 6d 65 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 22 } //1 z:\Programme\Internet Explorer\iexplore.exe "
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}