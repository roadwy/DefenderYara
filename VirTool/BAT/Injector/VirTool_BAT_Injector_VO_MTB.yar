
rule VirTool_BAT_Injector_VO_MTB{
	meta:
		description = "VirTool:BAT/Injector.VO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 17 72 ?? ?? 00 70 a2 11 09 18 28 33 00 00 0a a2 11 09 14 14 14 28 20 00 00 0a 28 11 00 00 0a 14 28 21 00 00 0a } //1
		$a_01_1 = {28 2f 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}