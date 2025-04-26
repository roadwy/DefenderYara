
rule HackTool_Win32_Capfetox_A_dha{
	meta:
		description = "HackTool:Win32/Capfetox.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {4c 6f 67 34 6a 5f 45 78 70 6c 6f 69 74 20 66 69 6e 61 6c } //Log4j_Exploit final  1
		$a_80_1 = {44 6e 73 4c 6f 67 5f 55 72 6c } //DnsLog_Url  1
		$a_80_2 = {56 50 53 5f 74 61 72 67 65 74 } //VPS_target  1
		$a_80_3 = {41 74 74 61 63 6b } //Attack  1
		$a_80_4 = {6e 69 63 65 30 65 33 } //nice0e3  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}