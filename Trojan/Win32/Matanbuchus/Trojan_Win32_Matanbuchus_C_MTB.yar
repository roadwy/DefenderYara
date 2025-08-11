
rule Trojan_Win32_Matanbuchus_C_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 45 14 8b 55 18 e8 ?? ?? ?? ?? 25 ff 00 00 00 0f be d0 8b 45 08 0f be 1c 30 33 da 6a 00 6a 01 8b 4d fc 51 8b 55 f8 52 e8 ?? ?? ?? ?? 8b 4d 08 88 1c 01 e9 } //2
		$a_03_1 = {68 88 01 01 10 8d 8d e0 fe ff ff e8 ?? ?? ?? ?? 68 8c 01 01 10 8d 8d e0 fe ff ff 51 8d 95 c8 fe ff ff 52 e8 ?? ?? ?? ?? 83 c4 0c 68 94 01 01 10 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}