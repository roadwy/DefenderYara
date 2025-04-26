
rule TrojanDropper_Win32_Rovnix_J{
	meta:
		description = "TrojanDropper:Win32/Rovnix.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 45 54 55 50 3a 20 53 74 61 72 74 65 64 20 61 73 20 77 69 6e 33 32 20 70 72 6f 63 65 73 73 20 30 78 25 78 } //1 SETUP: Started as win32 process 0x%x
		$a_00_1 = {53 45 54 55 50 3a 20 4e 6f 20 6a 6f 69 6e 65 64 20 42 4b 20 6c 6f 61 64 65 72 20 66 6f 75 6e 64 } //1 SETUP: No joined BK loader found
		$a_00_2 = {53 65 74 75 70 3a 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 66 61 69 6c 65 64 20 57 72 69 74 65 53 65 63 74 6f 72 73 } //1 Setup: Installation failed WriteSectors
		$a_00_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 30 00 5c 00 50 00 61 00 72 00 74 00 69 00 74 00 69 00 6f 00 6e 00 25 00 75 00 } //1 \Device\Harddisk0\Partition%u
		$a_00_4 = {53 65 74 75 70 3a 20 50 61 79 6c 6f 61 64 20 6f 66 20 25 75 20 62 79 74 65 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 77 72 69 74 74 65 6e 20 61 74 20 73 65 63 74 6f 72 20 25 78 } //1 Setup: Payload of %u bytes successfully written at sector %x
		$a_01_5 = {8d 49 08 8d 34 c8 b9 46 4a 00 00 0f b7 06 } //3
		$a_01_6 = {8b 04 b3 03 c2 33 47 0a 0f b6 ca d3 c0 46 4a 89 44 b3 fc 3b 75 08 72 e8 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=4
 
}