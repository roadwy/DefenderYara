
rule HackTool_Win64_Sucipik_MBWQ_MTB{
	meta:
		description = "HackTool:Win64/Sucipik.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d0 44 89 7c 24 40 48 8d 85 d8 04 00 00 c7 44 24 38 02 00 00 00 45 33 c9 48 89 44 24 30 4c 89 7c 24 28 4c 89 7c 24 20 ff ?? 44 8b 85 98 02 00 00 33 d2 b9 ff ff 1f 00 ff ?? c4 cd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}