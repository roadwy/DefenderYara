
rule Trojan_Win64_StormWiper_A_dha{
	meta:
		description = "Trojan:Win64/StormWiper.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 3f 00 3f 00 5c 00 5a 00 3a 00 5c 00 } //1 \??\Z:\
		$a_01_1 = {57 00 6f 00 72 00 6b 00 69 00 6e 00 67 00 20 00 6f 00 6e 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 2e 00 20 00 44 00 6f 00 6e 00 27 00 74 00 20 00 74 00 75 00 72 00 6e 00 20 00 6f 00 66 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 50 00 43 00 20 00 2e 00 2e 00 } //1 Working on updates. Don't turn off your PC ..
		$a_42_2 = {04 00 00 00 f3 aa 48 90 02 30 c7 44 24 90 01 01 00 00 01 00 48 81 7c 24 90 01 01 00 00 01 00 90 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_42_2  & 1)*1) >=3
 
}