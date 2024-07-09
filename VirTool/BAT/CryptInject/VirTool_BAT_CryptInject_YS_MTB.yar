
rule VirTool_BAT_CryptInject_YS_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 07 11 07 13 08 11 08 1f ?? d6 13 09 11 08 1f 5a 30 0b 11 08 1f 41 fe 04 16 fe 01 2b 01 16 13 0a 11 0a 13 0c 11 0c 2c 42 11 09 1f 5a fe 02 13 ?? 11 ?? 13 0f 11 0f 2c 16 11 09 1f 5a da 13 10 1f 40 11 10 d6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}