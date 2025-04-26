
rule Trojan_Win32_Rozena_BQ_MTB{
	meta:
		description = "Trojan:Win32/Rozena.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 18 00 00 eb 01 c7 44 24 1c 5c 52 b2 60 c7 44 24 20 31 d2 5a d5 c7 44 24 24 55 24 b1 e5 c7 44 24 28 46 01 7c 80 c7 44 24 2c 6c 00 00 d5 c7 44 24 30 9b 39 b4 b7 c7 44 24 34 b0 53 5e a0 c7 44 24 38 99 05 e3 32 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}