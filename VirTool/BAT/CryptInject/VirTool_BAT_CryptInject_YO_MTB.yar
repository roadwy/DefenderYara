
rule VirTool_BAT_CryptInject_YO_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {17 da 91 1f ?? 61 [0-02] 02 8e ?? 17 d6 [0-07] 02 8e ?? 17 da [0-0a] 11 ?? 02 11 ?? 91 [0-02] 61 07 [0-02] 91 61 b4 9c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}