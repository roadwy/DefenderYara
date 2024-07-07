
rule VirTool_WinNT_Rootkitdrv_LE{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 25 00 77 00 73 00 } //1 \DosDevices\C:\windows\system32\%ws
		$a_01_1 = {85 c0 74 32 8b 75 2c 8b 7d 24 83 6d 24 14 83 6d 2c 14 8b c3 2b 45 1c 48 8d 0c 80 c1 e1 02 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 ff 4d 1c f3 a4 8b 75 18 8b 7d 20 4b } //1
		$a_03_2 = {8d 34 10 f3 a5 8b 4b 3c 8b c3 2b 44 19 34 33 ff 33 d2 39 3d 90 01 04 7e 14 8b 0d 90 01 04 8d 0c 91 01 01 42 3b 15 90 01 04 7c ec 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}