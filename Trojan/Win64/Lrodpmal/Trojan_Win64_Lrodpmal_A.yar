
rule Trojan_Win64_Lrodpmal_A{
	meta:
		description = "Trojan:Win64/Lrodpmal.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 89 4d ?? 8b 55 ?? 83 c2 04 89 55 } //1
		$a_01_1 = {8b 4d 64 8b 11 03 55 08 8b 45 64 89 10 eb } //1
		$a_01_2 = {8b 45 6c 8b 48 2c 8b 55 60 66 0f be 04 11 8b 4d 60 8b 55 48 66 89 04 4a 8b 45 60 83 c0 01 89 45 60 eb cc } //1
		$a_01_3 = {50 6c 75 70 72 6f 75 6c 64 65 65 67 2e 6f 72 6c 6f } //1 Pluprouldeeg.orlo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}