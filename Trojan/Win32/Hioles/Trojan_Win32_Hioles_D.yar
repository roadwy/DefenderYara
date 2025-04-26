
rule Trojan_Win32_Hioles_D{
	meta:
		description = "Trojan:Win32/Hioles.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 51 40 30 11 66 0f be 88 ?? ?? ?? ?? ba ?? ?? 00 00 66 0f af ca } //1
		$a_01_1 = {66 8b c8 c1 e0 08 66 c1 e9 08 66 33 c8 8b 45 08 89 45 f4 } //1
		$a_03_2 = {8b 0b 81 f9 47 45 54 20 74 ?? 81 f9 50 4f 53 54 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}