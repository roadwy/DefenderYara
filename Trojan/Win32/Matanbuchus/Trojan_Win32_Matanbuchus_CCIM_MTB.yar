
rule Trojan_Win32_Matanbuchus_CCIM_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.CCIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 01 8b 4d fc 83 d1 00 89 45 f8 89 4d fc 8b 55 fc 3b 55 10 } //2
		$a_03_1 = {6a 00 6a 01 8b 4d fc 51 8b 55 f8 52 e8 ?? ?? ?? ?? 8b f0 6a 00 6a 08 8b 45 fc 50 8b 4d f8 51 e8 } //2
		$a_03_2 = {0f be d0 8b 45 08 0f be 1c 30 33 da 6a 00 6a 01 8b 4d fc 51 8b 55 f8 52 e8 ?? ?? ?? ?? 8b 4d 08 88 1c 01 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=5
 
}