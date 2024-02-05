
rule Trojan_Win64_Cobaltstrike_RUS_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 c1 e0 3a 49 c1 e2 34 4d 09 c2 49 c1 e3 2e 4d 09 d3 49 c1 e7 28 4d 09 df 48 c1 e2 22 4c 09 fa 48 c1 e5 1c 48 09 d5 48 c1 e1 16 48 09 e9 48 c1 e6 10 48 09 ce ba 08 00 00 00 31 c9 49 89 c0 e8 90 01 04 48 0f ce 48 89 74 24 90 00 } //01 00 
		$a_01_1 = {33 36 30 73 64 74 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}