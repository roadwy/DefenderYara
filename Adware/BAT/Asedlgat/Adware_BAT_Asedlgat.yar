
rule Adware_BAT_Asedlgat{
	meta:
		description = "Adware:BAT/Asedlgat,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 40 4c 46 58 32 } //1 4@LFX2
		$a_01_1 = {34 40 4c 46 58 32 53 39 } //1 4@LFX2S9
		$a_01_2 = {52 65 76 69 76 61 6c 4d 46 2e 4e 65 77 2e 78 6c 73 } //1 RevivalMF.New.xls
		$a_01_3 = {3a 5c 55 73 65 72 73 5c 57 69 7a 7a 6c 61 62 73 5c 50 69 63 74 75 72 65 73 5c 53 61 76 65 64 20 50 69 63 74 75 72 65 73 5c 54 72 69 63 6b 54 72 69 63 6b 5c 53 68 6f 77 4c 6f 76 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 52 65 76 69 76 61 6c 4d 46 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}