
rule VirTool_WinNT_Hyflid_A{
	meta:
		description = "VirTool:WinNT/Hyflid.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 4c 6a 00 e8 90 01 02 00 00 0b c0 0f 84 90 01 01 00 00 00 a3 90 01 02 01 00 6a 00 68 4b 53 70 79 6a 10 6a 00 6a 00 6a 00 90 00 } //1
		$a_01_1 = {59 c9 c2 04 00 fa 50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 c3 50 0f 20 c0 0d 00 00 01 00 0f 22 c0 58 fb c3 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}