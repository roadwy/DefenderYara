
rule VirTool_BAT_CryptInject_YT_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 0f 00 fe 16 90 01 03 01 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 9a 72 90 01 03 70 7e 90 01 03 0a 6f 90 01 03 0a 72 90 01 03 70 7e 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a d2 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}