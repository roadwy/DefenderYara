
rule Trojan_Win64_ShellCodeRunner_AMG_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.AMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d0 89 85 ?? ?? 00 00 8b 85 90 1b 00 00 00 41 89 c0 ba 00 00 00 00 b9 ff ff ?? ?? 48 8b 05 ?? ?? ?? ?? ff d0 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 c7 44 24 20 40 00 00 00 41 b9 00 10 00 00 41 b8 17 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 } //4
		$a_00_1 = {57 00 50 00 43 00 54 00 68 00 64 00 45 00 78 00 52 00 73 00 46 00 53 00 6e 00 67 00 4f 00 62 00 6a 00 51 00 49 00 66 00 70 00 47 00 44 00 } //1 WPCThdExRsFSngObjQIfpGD
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1) >=5
 
}