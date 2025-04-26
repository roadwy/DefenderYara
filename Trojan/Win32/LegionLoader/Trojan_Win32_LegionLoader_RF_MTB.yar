
rule Trojan_Win32_LegionLoader_RF_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8b 08 c1 e1 06 8b 55 f4 8b 02 c1 e8 08 33 c8 8b 55 f4 8b 32 03 f1 8b 45 fc 33 d2 f7 75 ec 8b 45 08 03 34 90 03 75 fc 8b 4d f0 8b 11 2b d6 8b 45 f0 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}