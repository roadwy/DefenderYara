
rule TrojanDownloader_Win32_Zlob_gen_Z{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 08 00 00 "
		
	strings :
		$a_01_0 = {7b 34 31 46 36 31 37 30 44 2d 36 41 46 38 2d 34 31 38 38 2d 38 44 39 32 2d 39 44 44 41 42 33 43 37 31 41 37 38 7d } //1 {41F6170D-6AF8-4188-8D92-9DDAB3C71A78}
		$a_01_1 = {7b 32 33 45 44 32 32 30 36 2d 38 35 36 44 2d 34 36 31 41 2d 42 42 43 46 2d 31 43 32 34 36 36 41 43 35 41 45 33 7d } //1 {23ED2206-856D-461A-BBCF-1C2466AC5AE3}
		$a_01_2 = {7b 30 36 32 46 33 46 38 42 2d 43 42 39 34 2d 34 44 37 36 2d 41 39 38 41 2d 45 46 38 30 30 41 34 33 38 46 30 31 7d } //1 {062F3F8B-CB94-4D76-A98A-EF800A438F01}
		$a_01_3 = {53 54 41 52 54 45 52 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 } //10
		$a_00_4 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 74 6f 6f 6c 62 61 72 5c 77 65 62 62 72 6f 77 73 65 72 } //10 software\microsoft\internet explorer\toolbar\webbrowser
		$a_00_5 = {63 72 65 61 74 65 74 6f 6f 6c 68 65 6c 70 33 32 73 6e 61 70 73 68 6f 74 } //10 createtoolhelp32snapshot
		$a_00_6 = {70 72 6f 63 65 73 73 33 32 6e 65 78 74 } //10 process32next
		$a_00_7 = {68 00 74 00 74 00 70 00 } //5 http
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*5) >=46
 
}