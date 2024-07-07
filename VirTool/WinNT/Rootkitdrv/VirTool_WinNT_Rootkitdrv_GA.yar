
rule VirTool_WinNT_Rootkitdrv_GA{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff ff 35 90 01 04 68 90 01 02 01 00 68 90 01 02 01 00 83 3c 24 00 75 0b 8d 54 24 0c 60 0e e8 48 00 00 00 83 2c 24 05 75 01 e8 c3 78 0b c0 75 08 b8 4f 00 00 c0 c2 08 00 75 06 0e e8 f4 fe ff ff 90 00 } //1
		$a_00_1 = {8b 40 34 0b c0 75 61 8b 54 24 04 6a 64 59 33 c0 66 81 3a c6 05 75 13 66 81 7a 06 01 e8 75 0b 83 c2 08 8b 02 8d 44 10 04 eb 03 42 e2 e3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}