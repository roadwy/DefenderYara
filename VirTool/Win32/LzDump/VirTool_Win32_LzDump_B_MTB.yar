
rule VirTool_Win32_LzDump_B_MTB{
	meta:
		description = "VirTool:Win32/LzDump.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 08 8b fc ff 15 90 01 04 3b fc e8 90 01 04 50 ff 15 90 01 04 3b f4 e8 90 01 04 85 c0 74 79 c7 45 d0 04 00 00 00 8b f4 8d 45 90 01 01 50 6a 04 8d 4d 90 01 01 51 6a 14 8b 55 e8 52 ff 90 00 } //1
		$a_02_1 = {c4 0c c7 85 a8 fd ff ff 2c 02 00 00 c7 85 9c fd ff ff 14 ae 42 00 8d 85 90 01 04 50 8b 4d dc 51 e8 90 00 } //1
		$a_02_2 = {c7 85 7c ff ff ff 00 00 00 00 c7 85 6c ff ff ff 00 00 00 00 c7 85 70 ff ff ff 00 00 00 00 c6 85 63 ff ff ff 01 8b f4 8d 85 90 01 04 50 6a 20 8b fc ff 90 00 } //1
		$a_00_3 = {8b 85 58 ff ff ff 50 8b 4d b8 51 8b 95 40 ff ff ff 52 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}