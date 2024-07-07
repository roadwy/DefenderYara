
rule Trojan_Win32_LegionLoader_RPR_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d fc 8b 55 fc 03 55 b0 89 55 fc 8b 45 f4 03 45 f8 89 45 f4 8b 4d fc 2b 4d b0 89 4d fc 8b 55 f8 2b 55 f4 89 55 f8 8b 45 f4 03 45 f8 89 45 f4 8b 8d 58 ff ff ff 8b 55 98 89 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}