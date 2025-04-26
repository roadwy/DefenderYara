
rule Trojan_Win32_Ekstak_PUAA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.PUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? 06 4c 00 68 ?? a3 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 7e 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7e 4c 00 c1 e1 08 03 ca 89 0d ?? 7e 4c 00 c1 e8 10 a3 ?? 7e 4c 00 6a 01 } //5
		$a_03_1 = {55 8b ec 6a ff 68 ?? f6 4b 00 68 ?? 93 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 7e 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7e 4c 00 c1 e1 08 03 ca 89 0d ?? 7e 4c 00 c1 e8 10 a3 ?? 7e 4c 00 6a 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}