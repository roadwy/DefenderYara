
rule HackTool_Win64_NoDefender_MBYK_MTB{
	meta:
		description = "HackTool:Win64/NoDefender.MBYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 84 24 ?? ?? ?? ?? 48 8b fa 48 63 f1 45 33 f6 33 d2 41 b8 98 01 } //1
		$a_03_1 = {48 8d 15 f1 99 06 00 48 8d 8c 24 00 03 00 00 e8 ?? ?? ?? 00 48 8b d8 } //1
		$a_01_2 = {2f 72 75 6e 61 73 73 76 63 20 2f 72 70 63 73 65 72 76 65 72 20 2f 77 73 63 5f 6e 61 6d 65 } //1 /runassvc /rpcserver /wsc_name
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}