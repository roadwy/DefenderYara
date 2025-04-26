
rule Trojan_Win32_Lethic_H{
	meta:
		description = "Trojan:Win32/Lethic.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 8c 01 f8 00 00 00 89 4d f8 68 ?? ?? ?? ?? 8b 55 f8 52 e8 ?? ?? ?? ?? 85 c0 74 0b 8b 45 f8 83 c0 28 89 45 f8 eb e3 } //1
		$a_01_1 = {68 d0 11 00 00 8b 55 ec 83 c2 0c 52 8b 45 e8 } //1
		$a_01_2 = {89 85 58 fd ff ff 33 c9 75 cb 8b 95 44 fd ff ff 81 c2 c8 11 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}