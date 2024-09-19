
rule HackTool_Win64_CobaltStrike_CR_ldr{
	meta:
		description = "HackTool:Win64/CobaltStrike.CR!ldr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d7 c1 c2 07 87 c7 33 c2 f7 d0 c1 c1 12 87 ?? 87 c2 4b f7 da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}