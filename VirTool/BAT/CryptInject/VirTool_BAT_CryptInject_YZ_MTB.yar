
rule VirTool_BAT_CryptInject_YZ_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8e 69 5d 91 06 03 7e ?? ?? ?? 04 8e 69 5d 58 03 5f 61 d2 61 d2 52 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}