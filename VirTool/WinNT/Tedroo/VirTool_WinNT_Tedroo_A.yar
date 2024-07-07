
rule VirTool_WinNT_Tedroo_A{
	meta:
		description = "VirTool:WinNT/Tedroo.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 63 65 70 74 20 74 61 73 6b 3a 20 44 65 66 65 6e 64 20 70 72 6f 63 65 73 73 20 25 64 } //1 Acept task: Defend process %d
		$a_00_1 = {41 63 65 70 74 20 74 61 73 6b 3a 20 48 69 64 65 20 70 72 6f 63 65 73 73 20 25 64 } //1 Acept task: Hide process %d
		$a_00_2 = {41 63 65 70 74 20 74 61 73 6b 3a 20 48 69 64 65 20 66 69 6c 65 20 25 64 } //1 Acept task: Hide file %d
		$a_02_3 = {fa 0f 20 c0 89 45 ec 25 ff ff fe ff 0f 22 c0 8b 0d 90 01 04 8b 11 a1 90 01 04 c7 04 82 90 01 04 8b 0d 90 01 04 8b 11 a1 90 01 04 c7 04 82 90 01 04 8b 0d 90 01 04 8b 11 a1 90 01 04 c7 04 82 90 01 04 8b 0d 90 01 04 8b 11 a1 90 01 04 c7 04 82 90 01 04 8b 45 ec 0f 22 c0 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10) >=11
 
}