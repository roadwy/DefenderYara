
rule Trojan_Win64_PirateStealer_BSA_MTB{
	meta:
		description = "Trojan:Win64/PirateStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f a2 89 c6 83 f8 00 74 33 81 fb 47 65 6e 75 75 1e 81 fa 69 6e 65 49 75 16 81 f9 6e 74 65 6c 75 0e c6 05 7d 9a 6e 00 01 c6 05 79 9a 6e 00 01 } //6
		$a_01_1 = {50 69 72 61 74 65 53 74 65 61 6c 65 72 42 54 57 61 70 70 6c 69 63 61 74 69 6f 6e } //6 PirateStealerBTWapplication
		$a_01_2 = {4c 6b 38 4a 77 33 4c 6f 4d 47 6c 75 53 4d 46 4b 38 59 74 6d } //2 Lk8Jw3LoMGluSMFK8Ytm
		$a_01_3 = {41 33 41 34 43 4e 43 63 43 66 43 6f 43 73 4c 6c 4c 6d 4c 6f 4c 74 4c 75 4d 63 4d 65 4d 6e 4e 64 4e 6c 4e 6f 4f 4b 4f 4e 4f 55 50 63 50 64 50 65 50 66 50 69 50 6f 50 73 53 54 53 63 53 6b 53 6d 53 6f 54 65 54 6f 56 31 56 32 56 33 56 35 56 36 59 69 5a 6c 5a 70 5a 73 } //2 A3A4CNCcCfCoCsLlLmLoLtLuMcMeMnNdNlNoOKONOUPcPdPePfPiPoPsSTScSkSmSoTeToV1V2V3V5V6YiZlZpZs
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*6+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}