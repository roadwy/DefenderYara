
rule Trojan_Win32_Vidar_RF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 31 bf 90 01 04 2b de 2b f9 eb 03 8d 49 00 8a 04 13 8d 52 01 34 90 01 01 88 42 ff 4f 75 f2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 01 88 06 88 11 0f b6 0e 0f b6 c2 03 c8 0f b6 c1 8b 8d 90 01 02 ff ff 0f b6 84 05 90 01 02 ff ff 30 04 0f 47 3b bd 3c f0 ff ff 72 b8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.RF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 4d f4 8d 14 07 31 55 fc } //1
		$a_01_1 = {8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}