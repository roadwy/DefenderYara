
rule TrojanSpy_Win32_Travnet_B{
	meta:
		description = "TrojanSpy:Win32/Travnet.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {c7 45 ec 60 ea 00 00 57 51 6a 02 50 ff d6 8d 45 ec 57 50 6a 05 ff 75 08 ff d6 8d 45 ec 57 50 6a 06 ff 75 08 ff d6 } //1
		$a_03_1 = {8b 4c 24 04 57 f7 c1 03 00 00 00 74 ?? 8a 01 41 84 c0 74 ?? f7 c1 03 00 00 00 75 ?? 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 } //1
		$a_00_2 = {25 73 6e 65 74 6d 67 72 2e } //1 %snetmgr.
		$a_00_3 = {4e 61 6d 65 3d 25 73 0a 50 61 67 65 3d 25 75 } //1
		$a_00_4 = {25 73 3f 61 63 74 69 6f 6e 3d 67 6f 74 63 6d 64 26 68 6f 73 74 69 64 } //1 %s?action=gotcmd&hostid
		$a_00_5 = {65 6e 75 6d 66 73 2e 69 6e 69 } //1 enumfs.ini
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}