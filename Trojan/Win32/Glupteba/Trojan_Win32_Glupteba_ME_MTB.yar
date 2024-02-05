
rule Trojan_Win32_Glupteba_ME_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 a3 90 02 09 e8 90 01 04 83 c4 04 8b 55 e8 52 90 02 05 e8 90 01 04 83 c4 08 8b 45 f0 8b 4d fc 8d 94 01 90 01 04 89 55 ec a1 90 01 04 a3 90 01 04 8b 4d ec 89 0d 90 01 04 8b 55 fc 83 c2 04 89 55 fc c7 45 90 01 05 c7 45 90 01 05 e8 90 01 04 b8 90 01 04 85 c0 0f 85 90 09 14 00 e8 90 01 04 a3 90 02 09 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_ME_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.ME!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 14 31 8d 41 40 30 02 41 83 f9 20 72 f2 } //01 00 
		$a_01_1 = {8d 14 31 8d 41 40 30 02 41 83 f9 05 72 f2 } //00 00 
	condition:
		any of ($a_*)
 
}