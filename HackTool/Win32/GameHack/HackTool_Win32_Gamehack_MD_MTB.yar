
rule HackTool_Win32_Gamehack_MD_MTB{
	meta:
		description = "HackTool:Win32/Gamehack.MD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 38 6a 00 6a 01 88 45 f8 8d 45 f8 50 57 ff 71 04 ff d3 8b 4d f4 47 8b 45 f0 83 ee 01 75 e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}