
rule Trojan_Win64_Rozena_AMBE_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 } //1
		$a_01_1 = {01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}