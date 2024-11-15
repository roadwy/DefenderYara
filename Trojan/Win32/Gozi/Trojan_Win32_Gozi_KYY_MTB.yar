
rule Trojan_Win32_Gozi_KYY_MTB{
	meta:
		description = "Trojan:Win32/Gozi.KYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d1 89 54 24 60 8b 54 24 2c 8b de 8a 04 10 0f af d9 6b db 0f 88 44 24 2b 8d 84 24 ?? ?? ?? ?? 50 2b df e8 } //5
		$a_03_1 = {03 d6 8b 74 24 68 0f b6 c9 03 ca 89 4c 24 3c 8b 54 24 3c 0f b6 c8 0f b7 05 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 3b c8 0f 4d 54 24 30 8d 46 04 3b f8 75 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}