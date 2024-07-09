
rule VirTool_WinNT_Tibs_gen_A{
	meta:
		description = "VirTool:WinNT/Tibs.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {7a 6c 63 6c 69 65 6e 74 } //zlclient  1
		$a_00_1 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0 } //1
		$a_01_2 = {00 00 8b 55 10 66 81 3a 4d 5a } //1
		$a_00_3 = {eb 22 0f 20 c0 50 25 ff ff fe ff 0f 22 c0 c6 01 33 c6 41 01 c0 c6 41 02 c2 c6 41 03 08 88 59 04 58 0f 22 c0 } //3
		$a_02_4 = {eb 91 57 56 89 75 30 e8 ?? ?? ff ff 03 f0 84 db 74 81 eb 19 3b 75 1c 75 09 c7 45 2c 06 00 00 80 } //3
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*3+(#a_02_4  & 1)*3) >=5
 
}