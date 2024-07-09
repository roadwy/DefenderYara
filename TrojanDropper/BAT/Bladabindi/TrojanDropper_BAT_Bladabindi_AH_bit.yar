
rule TrojanDropper_BAT_Bladabindi_AH_bit{
	meta:
		description = "TrojanDropper:BAT/Bladabindi.AH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 00 61 00 63 00 6b 00 65 00 64 00 00 ?? 74 00 68 00 65 00 64 00 61 00 79 00 73 00 2e } //2
		$a_01_1 = {49 00 2e 00 41 00 2e 00 4d 00 2e 00 42 00 2e 00 41 00 2e 00 43 00 2e 00 4b 00 } //1 I.A.M.B.A.C.K
		$a_01_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM AntivirusProduct
		$a_03_3 = {5c 57 6f 72 6d 90 04 01 02 20 2d 43 6c 69 65 6e 74 90 04 01 02 20 2d 4e 6f 72 6d 61 6c 44 6f 77 6e 6c 6f 61 64 65 72 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}