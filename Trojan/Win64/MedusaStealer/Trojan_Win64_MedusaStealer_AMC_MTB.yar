
rule Trojan_Win64_MedusaStealer_AMC_MTB{
	meta:
		description = "Trojan:Win64/MedusaStealer.AMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 84 05 10 04 00 00 30 04 0e 48 8b 85 50 04 00 00 48 ff c0 48 89 85 50 04 00 00 48 ff c1 4c 39 e1 } //1
		$a_81_1 = {39 6e 66 54 4a 4a 6f 77 79 7a 5a 52 44 53 6e 69 53 41 36 78 44 4b 55 6a 59 79 51 59 77 61 56 76 5a 39 4d 58 2b 6b 31 56 37 6b 3d } //1 9nfTJJowyzZRDSniSA6xDKUjYyQYwaVvZ9MX+k1V7k=
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}