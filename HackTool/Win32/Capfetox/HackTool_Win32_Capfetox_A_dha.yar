
rule HackTool_Win32_Capfetox_A_dha{
	meta:
		description = "HackTool:Win32/Capfetox.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4c 6f 67 34 6a 5f 45 78 70 6c 6f 69 74 20 66 69 6e 61 6c } //Log4j_Exploit final  01 00 
		$a_80_1 = {44 6e 73 4c 6f 67 5f 55 72 6c } //DnsLog_Url  01 00 
		$a_80_2 = {56 50 53 5f 74 61 72 67 65 74 } //VPS_target  01 00 
		$a_80_3 = {41 74 74 61 63 6b } //Attack  01 00 
		$a_80_4 = {6e 69 63 65 30 65 33 } //nice0e3  00 00 
		$a_00_5 = {5d 04 00 } //00 01 
	condition:
		any of ($a_*)
 
}