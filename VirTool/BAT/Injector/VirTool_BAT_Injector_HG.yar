
rule VirTool_BAT_Injector_HG{
	meta:
		description = "VirTool:BAT/Injector.HG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 17 da 13 ?? 16 13 ?? 2b ?? ?? 11 ?? 02 11 ?? 91 ?? 61 [0-04] 91 61 9c ?? 28 } //1
		$a_01_1 = {4b 49 53 53 4d 41 44 49 43 4b } //1 KISSMADICK
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}