
rule VirTool_WinNT_Desog_A{
	meta:
		description = "VirTool:WinNT/Desog.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 ff 89 3d d0 32 01 00 74 30 8b 45 fc 8d 73 0c 8d 48 02 33 c0 8b d1 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8b 4b 08 8b 3d d0 32 01 00 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 } //1
		$a_01_1 = {80 30 8d 8a 18 88 58 fc 40 e2 f5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}