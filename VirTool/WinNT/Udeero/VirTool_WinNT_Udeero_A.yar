
rule VirTool_WinNT_Udeero_A{
	meta:
		description = "VirTool:WinNT/Udeero.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 0c 20 00 80 74 90 01 01 3d 10 20 00 80 74 0c c7 45 f8 0d 00 00 c0 e9 90 00 } //3
		$a_00_1 = {5b 67 5f 6e 43 75 72 72 52 65 70 6c 61 63 65 44 61 74 61 4c 65 6e 20 3c 3d 20 30 5d } //1 [g_nCurrReplaceDataLen <= 0]
		$a_00_2 = {5b 4d 6f 64 69 66 79 50 61 63 6b 65 74 20 68 6f 6f 6b 5d } //1 [ModifyPacket hook]
		$a_00_3 = {5b 47 45 54 20 49 6f 20 44 61 74 61 5d } //1 [GET Io Data]
		$a_00_4 = {5b 67 6f 74 6f 20 52 65 66 65 6c 73 65 5d } //1 [goto Refelse]
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}