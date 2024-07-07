
rule VirTool_WinNT_Rootkitdrv_KZ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a d0 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 4b 04 8b 3b 03 7d 90 01 01 8b c1 8d 73 08 c1 e9 02 f3 a5 90 00 } //1
		$a_01_1 = {ff 45 08 83 c3 18 8b 45 08 3b 47 7c 7c } //1
		$a_03_2 = {6a 04 68 00 00 10 00 6a 01 8d 45 90 01 01 50 56 68 e8 03 00 00 56 8d 45 90 01 01 50 6a ff ff 75 90 01 01 ff 15 90 01 04 3d 03 00 00 40 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}