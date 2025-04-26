
rule VirTool_Win64_CobaltStrike_F_entry{
	meta:
		description = "VirTool:Win64/CobaltStrike.F!entry,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3 41 b8 ?? ?? ?? ?? 68 04 00 00 00 5a 48 89 f9 ff d0 00 00 00 00 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}