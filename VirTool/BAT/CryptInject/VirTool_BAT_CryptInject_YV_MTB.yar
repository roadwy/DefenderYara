
rule VirTool_BAT_CryptInject_YV_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {1f 10 5d 91 61 d2 52 00 90 01 01 17 d6 90 01 03 fe 02 16 fe 01 13 90 01 01 11 90 01 01 2d 90 01 01 06 13 90 01 01 2b 00 11 90 01 01 2a 90 00 } //1
		$a_02_1 = {14 fe 01 0d 09 90 01 02 00 06 7b 90 01 03 04 28 90 01 03 06 13 04 06 11 04 28 90 01 03 06 28 90 01 03 06 7d 90 01 03 04 00 06 7b 90 01 03 04 28 90 01 03 0a 0b 07 14 72 90 01 03 70 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}