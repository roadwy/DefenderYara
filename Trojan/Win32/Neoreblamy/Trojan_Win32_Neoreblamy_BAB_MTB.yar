
rule Trojan_Win32_Neoreblamy_BAB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 4e 67 54 46 79 42 70 78 63 46 65 70 75 61 4d 6f 58 6c 55 78 50 69 46 47 50 65 6a 47 6e 6e 45 4f 70 } //1 TNgTFyBpxcFepuaMoXlUxPiFGPejGnnEOp
		$a_01_1 = {76 47 63 55 66 47 74 59 51 76 66 73 70 77 7a 49 45 61 74 50 44 51 64 42 78 4b 79 64 52 48 } //1 vGcUfGtYQvfspwzIEatPDQdBxKydRH
		$a_01_2 = {4f 52 62 4b 63 4e 66 53 50 4d 65 53 4a 75 76 55 76 41 52 42 4d 54 4b 58 70 62 55 58 67 } //1 ORbKcNfSPMeSJuvUvARBMTKXpbUXg
		$a_01_3 = {67 48 46 4e 75 79 44 57 69 6b 4a 56 46 49 46 66 4f 4b 44 4f 61 62 6b 5a 50 43 64 62 51 4d 55 6e 7a 4b 64 6f 7a 64 6b 77 64 43 6b 4e 4b 62 61 4e 4f 78 52 44 66 64 59 44 4e 4c 49 46 4f 61 48 66 72 59 50 52 43 50 70 6b 70 4b 4e 70 65 41 66 42 6d 67 53 54 4d 45 41 58 6e } //1 gHFNuyDWikJVFIFfOKDOabkZPCdbQMUnzKdozdkwdCkNKbaNOxRDfdYDNLIFOaHfrYPRCPpkpKNpeAfBmgSTMEAXn
		$a_01_4 = {62 4a 7a 41 5a 76 6b 4b 62 54 59 4d 78 41 42 4c 54 4e 45 55 70 4e 64 52 41 4a 67 74 71 77 } //1 bJzAZvkKbTYMxABLTNEUpNdRAJgtqw
		$a_01_5 = {4b 62 77 47 47 7a 75 6d 4b 42 54 43 41 52 52 61 6b 55 41 48 45 6e 75 54 64 68 6c 72 } //1 KbwGGzumKBTCARRakUAHEnuTdhlr
		$a_01_6 = {4f 4f 51 79 68 46 45 43 78 53 49 52 73 43 6a 63 42 71 6a 67 73 42 68 77 67 56 58 4f 62 45 72 57 43 62 } //1 OOQyhFECxSIRsCjcBqjgsBhwgVXObErWCb
		$a_01_7 = {7a 67 69 72 70 57 55 5a 41 43 77 56 56 63 64 4a 4a 4e 5a 6d 42 63 5a 55 59 4c 44 78 63 49 67 51 43 48 4b 47 } //1 zgirpWUZACwVVcdJJNZmBcZUYLDxcIgQCHKG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}