
rule Trojan_Win32_Crusis_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Crusis.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 c0 01 89 45 f4 8b 4d fc 8b 55 fc 8b 44 8d b8 2b 44 95 b4 2b 05 ?? ?? ?? ?? 39 45 f4 73 27 8b 4d fc 8b 55 f4 03 54 8d b4 03 15 ?? ?? ?? ?? 8b 45 fc 8b 4d dc 8b 04 81 8b 4d f4 8b 75 ec 8a 14 16 88 14 08 eb b7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}