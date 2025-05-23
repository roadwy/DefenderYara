
rule VirTool_WinNT_FURootkit_BG{
	meta:
		description = "VirTool:WinNT/FURootkit.BG,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 0c 00 00 "
		
	strings :
		$a_00_0 = {65 6d 00 56 57 ff 15 } //2
		$a_00_1 = {01 00 46 81 fe 00 30 00 00 7c d9 } //1
		$a_00_2 = {01 00 8b 74 24 08 6a 10 03 c8 51 56 } //1
		$a_00_3 = {47 66 5f 00 55 8b ec 83 ec 1c 53 56 8d 45 e4 50 e8 } //2
		$a_00_4 = {8b 74 24 0c 83 66 18 00 32 d2 8b ce ff 15 } //1
		$a_00_5 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 } //2
		$a_00_6 = {89 14 81 0f 20 c0 0d 00 00 01 00 0f 22 c0 } //2
		$a_00_7 = {8b 41 01 8b 12 8b 04 82 a3 } //1
		$a_01_8 = {52 6f 6f 74 6b 69 74 } //1 Rootkit
		$a_01_9 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_10 = {68 69 64 69 6e 67 20 70 72 6f 63 65 73 73 2c 20 70 69 64 3a 20 25 64 } //2 hiding process, pid: %d
		$a_00_11 = {5c 48 69 64 65 5f 53 72 63 5c } //1 \Hide_Src\
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*2+(#a_00_11  & 1)*1) >=11
 
}