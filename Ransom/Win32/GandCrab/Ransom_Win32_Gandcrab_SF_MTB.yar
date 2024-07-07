
rule Ransom_Win32_Gandcrab_SF_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 45 c8 c7 85 78 ff ff ff 56 69 72 74 c7 85 7c ff ff ff 75 61 6c 41 c7 45 80 6c 6c 6f 63 83 65 84 00 8d 85 78 ff ff ff 50 ff 75 c8 ff 55 a0 89 45 b8 c7 85 78 ff ff ff 56 69 72 74 c7 85 7c ff ff ff 75 61 6c 50 c7 45 80 72 6f 74 65 c7 45 84 63 74 00 00 8d 85 78 ff ff ff 50 ff 75 c8 ff 55 a0 89 45 dc c7 85 78 ff ff ff 56 69 72 74 c7 85 7c ff ff ff 75 61 6c 46 c7 45 80 72 65 65 00 8d 85 78 ff ff ff 50 ff 75 c8 ff 55 a0 } //1
		$a_01_1 = {c7 45 d8 47 65 74 50 c7 45 dc 72 6f 63 41 c7 45 e0 64 64 72 65 c7 45 e4 73 73 00 00 eb 07 } //1
		$a_01_2 = {8b 95 1c ff ff ff 8b 32 2b f0 8b 42 04 1b c1 8b 8d 70 ff ff ff 33 d2 03 f1 13 c2 8b 8d 1c ff ff ff 89 31 89 41 04 e9 1c ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}