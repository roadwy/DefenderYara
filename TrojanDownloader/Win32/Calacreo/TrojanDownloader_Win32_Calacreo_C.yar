
rule TrojanDownloader_Win32_Calacreo_C{
	meta:
		description = "TrojanDownloader:Win32/Calacreo.C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_08_0 = {33 00 31 00 2e 00 32 00 31 00 34 00 2e 00 31 00 34 00 30 00 2e 00 32 00 31 00 34 00 } //5 31.214.140.214
		$a_08_1 = {33 00 31 00 2e 00 33 00 31 00 2e 00 37 00 35 00 2e 00 36 00 33 00 } //5 31.31.75.63
		$a_08_2 = {26 00 70 00 3d 00 62 00 6f 00 74 00 } //5 &p=bot
		$a_01_3 = {83 c0 3c 8b 00 03 45 f4 89 45 f0 8b 45 f0 8b 40 78 03 45 f4 } //2
		$a_08_4 = {5c 00 4f 00 70 00 65 00 72 00 61 00 5c 00 4f 00 70 00 65 00 72 00 61 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 5f 00 68 00 69 00 73 00 74 00 6f 00 72 00 79 00 2e 00 64 00 61 00 74 00 } //1 \Opera\Opera\global_history.dat
		$a_09_5 = {43 3a 5c 53 61 6e 64 62 6f 78 } //1 C:\Sandbox
	condition:
		((#a_08_0  & 1)*5+(#a_08_1  & 1)*5+(#a_08_2  & 1)*5+(#a_01_3  & 1)*2+(#a_08_4  & 1)*1+(#a_09_5  & 1)*1) >=13
 
}