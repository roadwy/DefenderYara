
rule VirTool_BAT_CryptInject_YX_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 16 0b 38 ?? ?? ?? 00 00 16 0c 2b ?? 00 02 07 08 6f ?? ?? ?? 0a 0d 02 16 16 6f ?? ?? ?? 0a 13 04 09 11 04 28 ?? ?? ?? 0a 13 ?? 11 ?? 2c ?? 00 17 8d ?? ?? ?? 01 13 ?? 11 ?? 16 12 ?? 28 ?? ?? ?? 0a 9c 06 19 8d ?? ?? ?? 01 25 16 12 ?? 28 ?? ?? ?? 0a 9c 25 17 12 ?? 28 ?? ?? ?? 0a 9c 25 18 11 ?? 16 91 9c 6f ?? ?? ?? 0a 00 00 00 08 17 58 0c 08 02 6f ?? ?? ?? 0a 17 59 fe 02 16 fe 01 13 ?? 11 ?? 2d ?? 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a 17 59 fe 02 16 fe 01 13 ?? 11 ?? 3a ?? ?? ?? ff 06 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 13 ?? 2b ?? 11 ?? 2a } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}