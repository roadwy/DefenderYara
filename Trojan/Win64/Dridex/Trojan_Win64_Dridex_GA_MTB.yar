
rule Trojan_Win64_Dridex_GA_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {43 8a 1c 11 8b 84 24 90 01 04 33 84 24 90 01 04 43 8a 34 10 40 28 de 89 84 24 90 01 04 4c 8b 84 24 90 01 04 4c 8b 8c 24 90 01 04 4c 29 c2 4c 29 c9 42 88 b4 14 90 01 04 49 01 ca 48 8b 4c 24 90 01 01 48 89 8c 24 90 01 04 4c 89 94 24 90 01 04 48 89 8c 24 90 01 04 49 39 d2 0f 84 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_GA_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_81_0 = {6f 6e 75 70 6b 72 65 61 73 6f 6e 69 6e 67 43 68 72 6f 6d 65 32 52 4c 5a 63 49 6e 74 65 72 6e 65 74 32 30 30 38 2e 32 38 } //0a 00 
		$a_02_1 = {42 8a 1c 0a 8b 44 24 90 01 01 83 f0 ff 48 8b 94 24 90 01 04 44 28 d3 48 29 d1 89 84 24 90 01 04 42 88 9c 0c 90 01 04 66 8b b4 24 90 01 04 66 83 f6 ff 66 89 b4 24 90 01 04 4d 01 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_GA_MTB_3{
	meta:
		description = "Trojan:Win64/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {48 29 c8 48 89 44 24 90 01 01 49 81 f0 90 01 04 44 8a 4c 24 01 41 80 c1 90 01 01 44 88 4c 24 90 01 01 44 8a 4c 24 90 01 01 48 8b 44 24 90 01 01 44 88 0c 10 44 8a 4c 24 90 01 01 41 80 e1 90 01 01 44 88 4c 24 90 01 01 4c 03 44 24 90 01 01 c6 44 24 90 01 01 58 48 8b 4c 24 90 01 01 4c 89 44 24 90 01 01 44 8a 4c 24 90 01 01 41 80 e9 90 01 01 44 88 4c 24 90 01 01 49 39 c8 0f 84 90 01 04 e9 90 00 } //01 00 
		$a_80_1 = {46 47 54 37 74 2e 70 64 62 } //FGT7t.pdb  01 00 
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_GA_MTB_4{
	meta:
		description = "Trojan:Win64/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {42 75 69 6c 64 74 68 65 73 6a 55 68 61 63 6b 65 72 73 69 6e 73 74 61 6e 63 65 } //BuildthesjUhackersinstance  01 00 
		$a_80_1 = {76 65 72 73 69 6f 6e 53 74 6f 72 65 2e 31 37 30 68 61 73 54 35 6f 66 5a 73 74 61 62 6c 65 53 } //versionStore.170hasT5ofZstableS  01 00 
		$a_80_2 = {74 79 70 65 64 6c 69 66 65 70 73 65 61 72 63 68 4d 61 79 79 61 6c 74 6f 67 65 74 68 65 72 2e 31 31 32 } //typedlifepsearchMayyaltogether.112  01 00 
		$a_80_3 = {69 6e 73 74 61 6c 6c 69 6e 67 69 72 65 78 75 70 64 61 74 65 73 2e 39 32 68 69 64 64 65 6e 38 30 76 69 6e 77 61 73 36 } //installingirexupdates.92hidden80vinwas6  01 00 
		$a_80_4 = {61 6e 79 49 6e 69 64 65 61 73 61 6e 64 53 61 74 79 70 65 64 70 58 } //anyInideasandSatypedpX  01 00 
		$a_80_5 = {77 61 73 55 74 68 61 74 47 6f 76 65 72 6e 6d 65 6e 74 } //wasUthatGovernment  01 00 
		$a_80_6 = {47 6f 6f 67 6c 65 65 6e 67 69 6e 65 66 61 73 74 65 72 74 75 72 6e 73 63 6f 74 74 53 50 } //GoogleenginefasterturnscottSP  01 00 
		$a_80_7 = {6c 42 65 6c 66 61 73 74 2c 66 69 6c 65 64 56 } //lBelfast,filedV  00 00 
	condition:
		any of ($a_*)
 
}