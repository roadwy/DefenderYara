
rule VirTool_BAT_CryptInject_BB_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 8e 69 1f 10 da 17 da 17 d6 8d ?? ?? ?? 01 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 1b 8d ?? ?? ?? 01 25 16 02 a2 25 17 1f 10 8c ?? ?? ?? 01 a2 25 18 06 a2 25 19 16 8c ?? ?? ?? 01 a2 25 1a 06 8e 69 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 06 26 06 8e 69 17 da 0b 16 0c 2b [0-02] 06 08 8f ?? ?? ?? 01 0d 09 09 47 02 08 1f 10 5d 91 61 d2 52 [0-01] 08 17 d6 0c 08 07 fe 02 16 fe [0-06] 2d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}