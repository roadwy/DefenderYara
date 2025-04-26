
rule Trojan_Win32_Ctoevade_G{
	meta:
		description = "Trojan:Win32/Ctoevade.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 83 e8 01 39 45 f8 7d 3f 8b 45 f8 8d 14 85 00 00 00 00 8b 45 08 01 d0 8b 00 89 c3 8b 45 0c 05 ff ff ff 3f 8d 14 85 00 00 00 00 8b 45 08 01 d0 8b 00 89 c1 8b 55 f8 8b 45 10 01 d0 31 cb 89 da 88 10 83 45 f8 01 eb b6 } //1
		$a_03_1 = {c7 00 47 45 54 20 c7 40 ?? 2f 72 65 73 c7 40 ?? 6f 75 72 63 c7 40 ?? 65 2e 68 74 c7 40 ?? 6d 6c 20 48 c7 40 ?? 54 54 50 2f c7 40 ?? 31 2e 31 0d 66 c7 40 ?? 0a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}