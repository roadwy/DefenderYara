
rule HackTool_Win64_Killgent_ZB_MTB{
	meta:
		description = "HackTool:Win64/Killgent.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {45 31 c0 45 89 c1 ba ff 01 0f 00 e8 [0-04] 48 89 c1 48 89 4d d0 48 89 85 } //1
		$a_02_1 = {8b 55 cc 48 8b 4d d0 48 c7 85 ?? 01 00 00 00 00 00 00 48 c7 85 ?? 01 00 00 00 00 00 00 4c 8d 45 f0 41 b9 00 01 00 00 4c 8d 95 ?? 01 00 00 48 8d 85 ?? 01 00 00 45 31 db 4c 89 54 24 20 c7 44 24 28 04 00 00 00 48 89 44 24 30 48 c7 44 24 38 00 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}