
rule VirTool_Win32_Afrootix{
	meta:
		description = "VirTool:Win32/Afrootix,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 3d a0 57 41 00 00 74 2b 68 18 37 41 00 a1 a0 57 41 00 50 e8 93 0f ff ff 8b f0 89 f3 85 f6 74 13 6a 00 b9 a4 57 41 00 ba f0 2e 41 00 8b c6 e8 64 b5 ff ff } //10
		$a_01_1 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
		$a_01_2 = {6e 65 74 73 74 61 74 2e 65 78 65 } //1 netstat.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
rule VirTool_Win32_Afrootix_2{
	meta:
		description = "VirTool:Win32/Afrootix,SIGNATURE_TYPE_PEHSTR,0c 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 c4 04 f0 ff ff 50 81 c4 84 fc ff ff 53 56 57 8b f1 8d 7d d0 a5 a5 a5 a5 89 55 fc 8b 5d 08 8b 45 d8 48 74 1e 83 e8 03 0f 84 37 02 00 00 48 0f 84 61 02 00 00 83 e8 04 0f 84 56 03 00 00 e9 a7 03 00 00 } //10
		$a_01_1 = {54 54 75 6e 6e 65 6c 35 38 2e 35 34 2e 35 31 2e 32 32 33 } //1 TTunnel58.54.51.223
		$a_01_2 = {54 54 75 6e 6e 65 6c 78 69 61 6f 79 75 30 39 31 37 2e 76 69 63 70 2e 6e 65 74 } //1 TTunnelxiaoyu0917.vicp.net
		$a_01_3 = {54 54 75 6e 6e 65 6c 70 68 6f 74 6f 61 6e 67 65 6c 31 31 31 2e 36 36 30 30 2e 6f 72 67 } //1 TTunnelphotoangel111.6600.org
		$a_01_4 = {54 54 75 6e 6e 65 6c 78 69 61 6f 7a 69 2e 33 33 32 32 32 2e 6f 72 67 } //1 TTunnelxiaozi.33222.org
		$a_01_5 = {54 54 75 6e 6e 65 6c 63 73 68 6f 77 2e 33 33 32 32 2e 6f 72 67 } //1 TTunnelcshow.3322.org
		$a_01_6 = {54 54 75 6e 6e 65 6c 6a 78 61 79 74 71 6c 2e 76 69 63 70 2e 63 63 } //1 TTunneljxaytql.vicp.cc
		$a_01_7 = {31 2e 32 2e 31 } //1 1.2.1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}