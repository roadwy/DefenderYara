
rule VirTool_Win32_Pucrpt_A_MTB{
	meta:
		description = "VirTool:Win32/Pucrpt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {be 0e 10 40 00 90 02 55 fc 90 02 05 ac 90 02 05 30 d0 90 02 05 aa 90 02 05 c1 ca 05 90 02 05 6b d2 07 90 02 05 f7 c3 01 00 00 00 90 02 15 83 c6 90 02 05 d1 cb 90 02 05 49 90 02 05 85 c9 90 00 } //01 00 
		$a_00_1 = {50 68 00 10 40 00 6a 00 6a 00 ff } //00 00 
	condition:
		any of ($a_*)
 
}