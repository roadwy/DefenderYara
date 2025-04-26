
rule Trojan_Win32_ICLoader_ANPA_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.ANPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? 86 79 00 68 ?? 25 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 9c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 9c b9 00 c1 e1 08 03 ca 89 0d ?? 9c b9 00 c1 e8 10 a3 ?? 9c b9 00 6a 01 } //5
		$a_03_1 = {55 8b ec 6a ff 68 ?? 86 79 00 68 ?? 26 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 8c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8c b9 00 c1 e1 08 03 ca 89 0d ?? 8c b9 00 c1 e8 10 a3 ?? 8c b9 00 6a 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}