
rule VirTool_Win32_Pastiche_A{
	meta:
		description = "VirTool:Win32/Pastiche.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b 05 0d 51 00 00 48 33 c4 48 89 44 24 40 48 90 01 04 4c 8b c1 48 89 44 24 28 4c 8d 90 01 05 48 8d 90 01 05 48 c7 44 24 20 00 00 00 00 48 8d 90 01 05 ff 15 90 01 04 85 c0 75 42 48 8b 4c 24 30 90 00 } //1
		$a_03_1 = {48 89 5c 24 50 ff 90 01 05 48 90 01 04 8b d8 ff 90 01 05 85 db 48 8b 5c 24 50 75 17 48 8b 44 24 38 48 8b 4c 24 40 48 33 cc e8 90 01 04 48 83 c4 58 c3 90 00 } //1
		$a_01_2 = {5c 70 69 70 65 5c 73 70 6f 6f 6c 73 73 } //1 \pipe\spoolss
		$a_01_3 = {6e 63 61 63 6e 5f 6e 70 } //1 ncacn_np
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}