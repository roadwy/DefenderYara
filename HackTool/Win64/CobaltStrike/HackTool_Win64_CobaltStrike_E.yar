
rule HackTool_Win64_CobaltStrike_E{
	meta:
		description = "HackTool:Win64/CobaltStrike.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 27 5b 8b 2b 83 c3 04 8b 13 31 ea 83 c3 04 53 8b 33 31 ee 89 33 31 f5 83 c3 04 83 ea 04 31 f6 39 f2 } //1
		$a_01_1 = {eb 33 5d 8b 45 00 48 83 c5 04 8b 4d 00 31 c1 48 83 c5 04 55 8b 55 00 31 c2 89 55 00 31 d0 48 83 c5 04 83 e9 04 31 d2 39 d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}