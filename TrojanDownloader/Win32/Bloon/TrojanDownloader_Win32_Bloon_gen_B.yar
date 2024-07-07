
rule TrojanDownloader_Win32_Bloon_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Bloon.gen!B,SIGNATURE_TYPE_PEHSTR,ffffffd3 00 ffffffd3 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 52 75 6e 2e 63 70 70 3a 41 64 64 41 70 70 6c 69 63 61 74 69 6f 6e 54 6f 52 65 67 69 73 74 72 79 52 75 6e 3a 20 52 65 67 43 72 65 61 74 65 4b 65 79 45 78 20 66 61 69 6c 65 64 } //100 AutoRun.cpp:AddApplicationToRegistryRun: RegCreateKeyEx failed
		$a_01_1 = {65 63 31 62 39 32 32 64 2d 38 33 38 64 2d 34 34 61 31 2d 61 32 65 66 2d 65 39 32 64 34 33 35 38 66 34 39 61 } //100 ec1b922d-838d-44a1-a2ef-e92d4358f49a
		$a_01_2 = {77 77 77 2e 6e 69 67 65 72 6f 76 2e 6e 65 74 } //10 www.nigerov.net
		$a_01_3 = {53 65 61 72 63 68 4d 61 69 64 20 54 72 61 79 49 43 4f 4e } //10 SearchMaid TrayICON
		$a_01_4 = {41 74 74 65 6e 74 69 6f 6e 21 20 46 61 69 6c 75 72 65 20 74 6f 20 64 65 6c 65 74 65 20 73 70 79 77 61 72 65 20 66 72 6f 6d 20 79 6f 75 72 20 50 43 20 63 61 6e 20 72 65 73 6c 75 74 20 69 6e 20 64 61 6d 61 67 65 } //1 Attention! Failure to delete spyware from your PC can reslut in damage
		$a_01_5 = {73 70 79 77 61 72 65 20 66 72 6f 6d 20 79 6f 75 72 20 6f 70 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 2e } //1 spyware from your operating system.
		$a_01_6 = {43 6c 69 63 6b 20 22 4f 4b 22 20 74 6f 20 67 65 74 20 61 6c 6c 20 61 76 61 69 6c 61 62 6c 65 20 41 6e 74 69 20 53 70 79 77 61 72 65 20 73 6f 66 74 77 61 72 65 2e } //1 Click "OK" to get all available Anti Spyware software.
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=211
 
}