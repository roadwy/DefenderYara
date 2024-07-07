
rule Trojan_Win32_Emotet_RV_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RV!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d2 83 ec 10 89 45 f4 8b 45 d4 8b 55 0c 89 54 24 08 8b 55 08 89 54 24 04 8b 55 f4 89 14 24 ff d0 8b 4d d8 8b 55 0c 8b 45 e8 89 54 24 18 8d 55 0c 89 54 24 14 8b 55 f4 89 54 24 10 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 ff d1 83 ec 1c 85 c0 0f 94 c0 84 c0 74 07 b8 00 00 00 00 eb 03 } //1
		$a_01_1 = {55 89 e5 53 83 ec 74 c7 04 24 c0 07 b6 69 e8 6e fe ff ff 89 45 d4 c7 04 24 dd 03 de 49 e8 5f fe ff ff 89 45 b4 c7 04 24 cf f3 4b 2c e8 50 fe ff ff 89 45 b8 c7 04 24 55 7a 8d 10 e8 41 fe ff ff 89 45 d8 c7 04 24 32 2f 83 c1 e8 32 fe ff ff 89 45 dc c7 04 24 a3 ed 12 b8 e8 23 fe ff ff 89 45 e0 c7 04 24 78 5d 52 4d e8 14 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}