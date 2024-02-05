
rule Ransom_Win32_GrandCrab_DA_MTB{
	meta:
		description = "Ransom:Win32/GrandCrab.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b bd f0 f7 ff ff ff 15 90 01 04 56 ff 15 90 01 04 e8 8f ff ff ff 30 04 1f 56 ff 15 90 01 04 56 ff 15 90 01 04 33 c0 89 b5 e8 f7 ff ff 8d bd ec f7 ff ff ab 8d 85 e8 f7 ff ff 50 56 56 56 ff 15 90 00 } //01 00 
		$a_02_1 = {75 40 39 74 24 90 01 01 75 34 68 90 01 04 c7 05 90 01 04 6b 65 72 6e c7 05 90 01 04 65 6c 33 32 c7 05 90 01 04 2e 64 6c 6c c6 05 90 01 04 00 ff 15 90 01 04 89 44 24 90 01 01 47 e9 61 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}