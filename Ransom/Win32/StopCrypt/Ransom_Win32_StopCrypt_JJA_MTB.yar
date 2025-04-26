
rule Ransom_Win32_StopCrypt_JJA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.JJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d ?? ?? ?? ?? 8c 07 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 75 } //1
		$a_03_1 = {50 6a 00 ff 15 ?? ?? ?? ?? 33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d ?? ?? ?? ?? 93 00 00 00 75 10 68 bc 2a 40 00 8d 4c 24 74 51 ff 15 80 10 40 00 81 c5 47 86 c8 61 ff 4c 24 18 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}