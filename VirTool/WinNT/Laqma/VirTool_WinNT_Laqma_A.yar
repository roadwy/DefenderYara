
rule VirTool_WinNT_Laqma_A{
	meta:
		description = "VirTool:WinNT/Laqma.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 85 d4 fd ff ff 74 1d 66 83 38 21 75 05 66 c7 00 5c 00 66 83 38 47 75 05 66 c7 00 52 00 40 40 66 39 38 } //1
		$a_01_1 = {8d 85 cc fd ff ff 74 1d 66 83 38 21 75 05 66 c7 00 5c 00 66 83 38 47 75 05 66 c7 00 52 00 03 c7 66 39 18 } //1
		$a_02_2 = {eb 32 8d 7b 5e be 90 01 01 90 03 01 01 05 06 01 00 a5 a5 a5 a5 c7 43 3c 10 00 00 00 fb 83 4d fc ff b8 0f 00 00 c0 e9 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}