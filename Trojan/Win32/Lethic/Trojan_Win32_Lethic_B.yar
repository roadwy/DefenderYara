
rule Trojan_Win32_Lethic_B{
	meta:
		description = "Trojan:Win32/Lethic.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 c1 8b 4d 08 88 01 8b 55 fc 83 c2 01 89 55 fc a1 } //2
		$a_01_1 = {6a 07 8b 55 08 83 c2 0c 52 ff 15 } //1
		$a_03_2 = {8b 4d 08 89 41 38 68 ?? ?? ?? ?? 8b 55 ?? 52 ff 15 } //1
		$a_03_3 = {8d 8c 01 f8 00 00 00 89 4d f8 68 ?? ?? ?? ?? 8b 55 f8 52 e8 ?? ?? ?? ?? 85 c0 74 0b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}