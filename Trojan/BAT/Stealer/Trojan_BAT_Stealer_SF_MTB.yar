
rule Trojan_BAT_Stealer_SF_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SF!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 6d 20 70 6e 7b 6e 6f 74 20 6f 72 2d 72 75 6e 20 76 7b 2d 44 4f 53 20 7a 7c 71 65 } //1 tram pn{not or-run v{-DOS z|qe
		$a_01_1 = {73 68 72 79 79 33 32 2e 64 79 79 } //1 shryy32.dyy
		$a_01_2 = {6b 65 72 6e 72 79 40 32 } //1 kernry@2
		$a_01_3 = {49 76 61 7b 2d 5a 65 64 76 65 71 72 } //1 Iva{-Zedveqr
		$a_01_4 = {41 34 46 45 34 35 46 44 34 36 41 41 36 33 36 30 31 43 46 44 41 34 42 42 35 42 37 45 32 37 39 41 32 31 45 31 44 36 45 32 36 33 41 43 33 46 37 38 46 32 37 42 45 46 34 32 36 39 44 43 32 30 31 31 } //1 A4FE45FD46AA63601CFDA4BB5B7E279A21E1D6E263AC3F78F27BEF4269DC2011
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}