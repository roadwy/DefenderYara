
rule HackTool_Win32_CobaltStrike_H{
	meta:
		description = "HackTool:Win32/CobaltStrike.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 5a 52 45 e8 00 00 00 00 5b 89 df 55 89 e5 81 c3 45 7d 00 00 ff d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}