
rule VirTool_WinNT_Protmin_gen_C{
	meta:
		description = "VirTool:WinNT/Protmin.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,28 00 1e 00 08 00 00 "
		
	strings :
		$a_00_0 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 4e 00 4e 00 49 00 43 00 5c 00 43 00 64 00 6e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 49 00 6e 00 66 00 6f 00 } //5 \REGISTRY\MACHINE\SOFTWARE\CNNIC\CdnClient\InstallInfo
		$a_00_1 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 64 00 6e 00 50 00 72 00 6f 00 74 00 } //5 \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\CdnProt
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 43 00 64 00 6e 00 50 00 72 00 6f 00 74 00 } //5 \Device\CdnProt
		$a_00_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 64 00 6e 00 50 00 72 00 6f 00 74 00 } //5 \DosDevices\CdnProt
		$a_02_4 = {45 58 50 4c 4f 52 45 52 2e 45 58 45 [0-05] 4d 53 48 54 41 2e 45 58 45 [0-05] 52 55 4e 44 4c 4c 33 32 2e 45 58 45 [0-05] 45 58 50 4c 4f 52 45 52 2e 45 58 45 } //5
		$a_02_5 = {3b f7 74 37 ff 75 10 ff 15 [0-05] 80 7d 14 00 59 8d 46 08 50 ff 75 10 74 0e ff 15 [0-05] 59 85 c0 59 75 12 eb 0c } //5
		$a_00_6 = {8d 3c 01 83 3c 01 83 c9 ff 33 c0 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 80 7d 08 00 74 35 8d 7d c0 83 c9 ff 33 c0 f2 ae f7 d1 49 39 4d 0c 76 23 8d 7d c0 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7 8b e9 02 f3 a5 8b c8 83 e1 03 f3 a4 eb 02 } //10
		$a_02_7 = {f2 ae f7 d1 83 c1 08 51 6a 01 ff [0-05] 8b f0 33 c0 3b f0 74 61 8b 7c 24 0c 53 50 50 50 bb [0-05] 50 53 89 3e ff 15 [0-05] c1 ef 02 81 e7 ff 00 00 00 8d 56 08 6a 00 53 } //10
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_02_4  & 1)*5+(#a_02_5  & 1)*5+(#a_00_6  & 1)*10+(#a_02_7  & 1)*10) >=30
 
}