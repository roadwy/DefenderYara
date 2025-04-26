
rule Worm_Win32_Silly_P2P_E{
	meta:
		description = "Worm:Win32/Silly_P2P.E,SIGNATURE_TYPE_PEHSTR_EXT,7f 00 7b 00 11 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //100 Software\Borland\Delphi\Locales
		$a_00_1 = {5c 53 6f 66 74 77 61 72 65 5c 4b 61 7a 61 61 5c 4c 6f 63 61 6c 43 6f 6e 74 65 6e 74 } //4 \Software\Kazaa\LocalContent
		$a_01_2 = {50 61 74 68 57 57 57 52 6f 6f 74 } //4 PathWWWRoot
		$a_01_3 = {3c 6d 65 74 61 20 68 74 74 70 2d 65 71 75 69 76 3d 22 72 65 66 72 65 73 68 22 20 63 6f 6e 74 65 6e 74 3d 22 31 3b 55 52 4c 3d } //4 <meta http-equiv="refresh" content="1;URL=
		$a_01_4 = {5c 4b 61 5a 61 61 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c } //4 \KaZaa\My Shared Folder\
		$a_01_5 = {2e 63 6f 6d 2f 66 6f 74 6f 30 } //3 .com/foto0
		$a_01_6 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c } //3 C:\Arquivos de programas\
		$a_01_7 = {5c 69 6e 64 65 78 2e 68 74 6d } //1 \index.htm
		$a_01_8 = {44 6f 77 6e 6c 6f 61 64 44 69 72 } //1 DownloadDir
		$a_01_9 = {53 79 73 74 65 6d 44 72 69 76 65 } //1 SystemDrive
		$a_01_10 = {5c 4d 79 20 44 6f 77 6e 6c 6f 61 64 73 5c } //1 \My Downloads\
		$a_01_11 = {5c 57 61 72 65 7a 20 50 32 50 20 43 6c 69 65 6e 74 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c } //1 \Warez P2P Client\My Shared Folder\
		$a_01_12 = {5c 4d 6f 72 70 68 65 75 73 5c 44 6f 77 6e 6c 6f 61 64 73 5c } //1 \Morpheus\Downloads\
		$a_01_13 = {5c 4b 4d 44 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c } //1 \KMD\My Shared Folder\
		$a_01_14 = {5c 42 65 61 72 53 68 61 72 65 5c 53 68 61 72 65 64 5c } //1 \BearShare\Shared\
		$a_01_15 = {5c 4b 61 5a 61 61 20 4c 69 74 65 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c } //1 \KaZaa Lite\My Shared Folder\
		$a_01_16 = {5c 47 72 6f 6b 73 74 65 72 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c } //1 \Grokster\My Shared Folder\
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=123
 
}