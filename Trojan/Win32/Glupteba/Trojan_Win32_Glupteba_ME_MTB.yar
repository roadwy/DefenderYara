
rule Trojan_Win32_Glupteba_ME_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 a3 [0-09] e8 ?? ?? ?? ?? 83 c4 04 8b 55 e8 52 [0-05] e8 ?? ?? ?? ?? 83 c4 08 8b 45 f0 8b 4d fc 8d 94 01 ?? ?? ?? ?? 89 55 ec a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 4d ec 89 0d ?? ?? ?? ?? 8b 55 fc 83 c2 04 89 55 fc c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 85 c0 0f 85 90 09 14 00 e8 ?? ?? ?? ?? a3 [0-09] e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_ME_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.ME!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 14 31 8d 41 40 30 02 41 83 f9 20 72 f2 } //1
		$a_01_1 = {8d 14 31 8d 41 40 30 02 41 83 f9 05 72 f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}