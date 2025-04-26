
rule Trojan_Win64_Viknok_A{
	meta:
		description = "Trojan:Win64/Viknok.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 41 0f b7 e9 8b fa 4c 8b 50 60 33 c0 48 8b d9 49 8b 72 18 } //1
		$a_03_1 = {eb 11 81 fb ?? ?? 00 00 73 18 b9 64 00 00 00 ff d6 ff c3 e8 ?? ?? ?? ?? 48 8b c8 ff d7 41 3b c7 74 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}