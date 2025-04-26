
rule HackTool_Win32_ZorSaw_A_dha{
	meta:
		description = "HackTool:Win32/ZorSaw.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {75 16 83 90 01 01 01 0f 85 90 01 04 81 90 01 01 18 00 01 00 00 0f 85 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}