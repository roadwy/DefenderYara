
rule VirTool_BAT_Obfuscator_BW{
	meta:
		description = "VirTool:BAT/Obfuscator.BW,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 02 11 05 91 [0-02] 61 [0-03] 91 61 9c [0-02] 28 ?? 00 00 0a [0-04] 8e b7 17 da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}