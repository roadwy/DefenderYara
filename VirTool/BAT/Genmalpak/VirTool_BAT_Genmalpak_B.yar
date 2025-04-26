
rule VirTool_BAT_Genmalpak_B{
	meta:
		description = "VirTool:BAT/Genmalpak.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 0a 08 11 0a 91 11 05 11 0a 09 5d 91 61 9c 11 0a 17 d6 13 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}