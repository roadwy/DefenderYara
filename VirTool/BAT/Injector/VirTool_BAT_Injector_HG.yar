
rule VirTool_BAT_Injector_HG{
	meta:
		description = "VirTool:BAT/Injector.HG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 17 da 13 90 01 01 16 13 90 01 01 2b 90 01 02 11 90 01 01 02 11 90 01 01 91 90 01 01 61 90 02 04 91 61 9c 90 01 01 28 90 00 } //1
		$a_01_1 = {4b 49 53 53 4d 41 44 49 43 4b } //1 KISSMADICK
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}