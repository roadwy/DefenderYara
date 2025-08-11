
rule Trojan_BAT_Msilheracles_PGM_MTB{
	meta:
		description = "Trojan:BAT/Msilheracles.PGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {49 55 64 6c 74 48 47 59 64 67 50 5a 65 49 61 4e 4e 49 72 4a 76 58 6d 4c 6c 64 2e 6b 6a 76 76 45 48 79 4f 6d 79 53 46 45 59 64 6c 66 45 79 4d 78 52 49 7a 68 4f 6e } //IUdltHGYdgPZeIaNNIrJvXmLld.kjvvEHyOmySFEYdlfEyMxRIzhOn  1
		$a_80_1 = {65 4f 6d 6e 57 61 42 54 76 4d 43 77 4e 46 51 63 77 6c 5a 41 53 76 79 45 57 4a 52 } //eOmnWaBTvMCwNFQcwlZASvyEWJR  4
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*4) >=5
 
}
rule Trojan_BAT_Msilheracles_PGM_MTB_2{
	meta:
		description = "Trojan:BAT/Msilheracles.PGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {6c 55 71 39 53 52 66 59 48 38 4b 6b 45 7a 4e 4b 46 7a 51 70 39 73 61 54 49 4b 64 58 30 44 6d 6e 52 68 33 4c 4f 33 4b 61 52 4d 49 3d } //lUq9SRfYH8KkEzNKFzQp9saTIKdX0DmnRh3LO3KaRMI=  2
		$a_80_1 = {77 5a 6b 35 4e 36 72 39 46 76 53 32 49 59 4d 52 33 51 51 70 73 51 3d 3d } //wZk5N6r9FvS2IYMR3QQpsQ==  2
		$a_01_2 = {46 44 37 34 41 46 46 42 33 46 41 44 43 32 46 46 33 30 42 33 30 43 32 30 35 33 43 33 31 36 39 31 37 35 46 34 38 42 44 33 42 32 38 32 42 32 45 37 41 30 46 43 36 45 34 33 36 46 33 39 42 33 36 36 } //1 FD74AFFB3FADC2FF30B30C2053C3169175F48BD3B282B2E7A0FC6E436F39B366
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}