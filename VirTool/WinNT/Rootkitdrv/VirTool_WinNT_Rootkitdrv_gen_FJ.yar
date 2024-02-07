
rule VirTool_WinNT_Rootkitdrv_gen_FJ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c0 04 8d 1d 90 01 04 2b d8 83 eb 05 c6 00 e8 89 58 01 9d 61 e8 90 01 04 33 c0 90 00 } //01 00 
		$a_02_1 = {c7 00 aa aa aa aa a1 90 01 04 c7 40 04 bb bb bb bb 6a 00 ff 35 90 01 04 ff 15 90 01 04 eb 90 00 } //01 00 
		$a_00_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 61 00 6b 00 39 00 32 00 32 00 2e 00 73 00 79 00 73 00 } //01 00  System32\drivers\ak922.sys
		$a_00_3 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 41 00 7a 00 79 00 4b 00 69 00 74 00 } //00 00  Services\AzyKit
	condition:
		any of ($a_*)
 
}