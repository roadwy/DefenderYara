
rule HackTool_Win64_EDRSandBlast_SA_MTB{
	meta:
		description = "HackTool:Win64/EDRSandBlast.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 89 45 ?? 8b 45 ?? 89 45 ?? 83 7d ?? ?? 7e ?? 8b 45 ?? 99 83 e0 ?? 33 c2 2b c2 85 c0 75 } //1
		$a_03_1 = {2b c2 d1 f8 89 45 ?? 8b 85 ?? ?? ?? ?? ff c0 89 85 ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}