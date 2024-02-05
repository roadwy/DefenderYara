
rule Trojan_Win64_ClipBanker_CL_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.CL!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 48 ff c6 88 07 48 ff c7 bb 02 00 00 00 00 d2 75 07 8a 16 48 ff c6 10 d2 73 e4 } //02 00 
		$a_01_1 = {05 6d 2c 10 28 8a 30 b1 7b 26 32 18 20 98 26 45 3c a1 a6 fa b2 4d 40 e6 96 26 74 8d } //01 00 
		$a_01_2 = {48 14 a0 10 94 84 38 09 2f db 30 26 d6 64 29 0e 7d 88 } //00 00 
	condition:
		any of ($a_*)
 
}