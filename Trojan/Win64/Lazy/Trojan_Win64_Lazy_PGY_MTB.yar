
rule Trojan_Win64_Lazy_PGY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 6d 61 6e 61 67 65 64 28 74 31 00 00 70 0b 00 00 76 31 00 00 64 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 } //1
		$a_01_1 = {68 79 64 72 61 74 65 64 10 9a 13 00 00 f0 3c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 c0 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}