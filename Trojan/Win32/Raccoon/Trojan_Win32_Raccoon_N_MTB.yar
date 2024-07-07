
rule Trojan_Win32_Raccoon_N_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 36 23 01 00 01 45 fc 90 02 05 03 45 08 8b 4d fc 03 4d 08 8a 11 88 10 90 00 } //1
		$a_00_1 = {8b 45 08 8b 08 33 4d 0c 8b 55 08 89 0a } //1
		$a_03_2 = {83 e9 14 88 0d 90 01 04 0f be 15 90 01 04 83 ea 14 88 15 90 01 04 0f be 05 90 01 04 83 e8 14 a2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}