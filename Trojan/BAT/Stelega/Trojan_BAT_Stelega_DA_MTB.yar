
rule Trojan_BAT_Stelega_DA_MTB{
	meta:
		description = "Trojan:BAT/Stelega.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 38 61 34 37 34 65 64 63 2d 36 36 35 38 2d 34 66 62 30 2d 38 39 31 66 2d 32 63 61 39 64 35 37 30 35 66 66 34 } //1 $8a474edc-6658-4fb0-891f-2ca9d5705ff4
		$a_81_1 = {7c 74 72 61 6d 20 70 6e 7b 6e 6f 74 20 6f 72 2d 72 75 6e 20 76 7b 2d 44 4f 53 20 7a 7c 71 65 2e } //1 |tram pn{not or-run v{-DOS z|qe.
		$a_81_2 = {57 61 76 65 50 61 64 20 53 6f 75 6e 64 20 45 64 69 74 6f 72 } //1 WavePad Sound Editor
		$a_81_3 = {4e 43 48 20 53 6f 66 74 77 61 72 65 } //1 NCH Software
		$a_81_4 = {63 6f 6e 6e 65 63 74 69 6f 6e 49 64 } //1 connectionId
		$a_81_5 = {2e 4e 52 61 53 72 61 6d 65 } //1 .NRaSrame
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}