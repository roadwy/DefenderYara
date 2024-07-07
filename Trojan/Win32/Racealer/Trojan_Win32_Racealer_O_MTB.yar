
rule Trojan_Win32_Racealer_O_MTB{
	meta:
		description = "Trojan:Win32/Racealer.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {b8 36 23 01 00 01 45 fc 90 02 08 03 55 08 8b 45 fc 03 45 08 8a 08 88 0a 90 00 } //1
		$a_00_1 = {c7 45 fc 04 00 00 00 8b 45 0c 8b 4d fc d3 e0 8b 4d 08 89 01 } //1
		$a_00_2 = {8b 45 08 8b 08 33 4d 0c 8b 55 08 89 0a } //1
		$a_00_3 = {8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a } //1
		$a_03_4 = {83 e9 14 88 0d 90 01 04 0f be 15 90 01 04 83 ea 14 88 15 90 01 04 0f be 05 90 01 04 83 e8 14 a2 90 01 04 0f be 0d 90 01 04 83 e9 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Racealer_O_MTB_2{
	meta:
		description = "Trojan:Win32/Racealer.O!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 01 08 c3 } //1
		$a_01_1 = {8a 94 01 3b 2d 0b 00 88 14 30 40 3b c7 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}