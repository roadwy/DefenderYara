
rule VirTool_Win32_Pucrpt_A_MTB{
	meta:
		description = "VirTool:Win32/Pucrpt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {be 0e 10 40 00 [0-55] fc [0-05] ac [0-05] 30 d0 [0-05] aa [0-05] c1 ca 05 [0-05] 6b d2 07 [0-05] f7 c3 01 00 00 00 [0-15] 83 c6 [0-05] d1 cb [0-05] 49 [0-05] 85 c9 } //1
		$a_00_1 = {50 68 00 10 40 00 6a 00 6a 00 ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}