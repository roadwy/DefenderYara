
rule TrojanSpy_Win32_Sibanner_A{
	meta:
		description = "TrojanSpy:Win32/Sibanner.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 f4 8b 45 f8 8a 0a 32 4c 05 fc 8b 55 08 03 55 f4 88 0a } //1
		$a_01_1 = {8b 55 f8 33 c0 8a 44 15 fc d1 f8 8b 4d f8 88 44 0d fc 8b 55 f8 8a 44 15 fc 0c 80 8b 4d f8 88 44 0d fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanSpy_Win32_Sibanner_A_2{
	meta:
		description = "TrojanSpy:Win32/Sibanner.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 f4 8b 45 f8 8a 0a 32 4c 05 fc 8b 55 08 03 55 f4 88 0a } //1
		$a_01_1 = {8b 55 f8 33 c0 8a 44 15 fc d1 f8 8b 4d f8 88 44 0d fc 8b 55 f8 8a 44 15 fc 0c 80 8b 4d f8 88 44 0d fc } //1
		$a_01_2 = {2f 62 61 6e 6e 65 72 32 2e 70 68 70 3f 6a 70 67 3d } //1 /banner2.php?jpg=
		$a_01_3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 75 73 65 72 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 } //1 Content-Disposition: form-data; name="userfile"; filename="%s"
		$a_01_4 = {25 73 5c 4c 53 50 25 30 34 64 2e 25 30 32 64 2e 25 30 32 64 5f 25 30 32 64 2e 25 30 32 64 2e 25 30 32 64 2e 74 6d 70 } //1 %s\LSP%04d.%02d.%02d_%02d.%02d.%02d.tmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}