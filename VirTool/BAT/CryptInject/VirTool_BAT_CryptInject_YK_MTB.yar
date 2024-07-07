
rule VirTool_BAT_CryptInject_YK_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {28 04 00 00 0a 28 05 00 00 0a 6f 06 00 00 0a 14 14 6f 07 00 00 0a 26 90 01 01 28 08 00 00 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}