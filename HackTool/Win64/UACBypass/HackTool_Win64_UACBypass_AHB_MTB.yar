
rule HackTool_Win64_UACBypass_AHB_MTB{
	meta:
		description = "HackTool:Win64/UACBypass.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 8d 00 02 00 00 48 8b 95 f0 01 00 00 49 89 c8 4c 89 c7 48 89 d1 f3 aa 48 89 ca 49 89 f8 } //30
		$a_01_1 = {c7 45 fc 22 00 00 c0 c7 45 f8 05 40 00 80 c7 45 f4 00 00 00 00 48 c7 45 e8 00 00 00 00 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}