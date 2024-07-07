
rule Trojan_Win32_Dridex_PP_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {65 73 7a 66 69 72 73 74 43 61 6e 64 37 55 6e 69 71 75 65 39 } //1 eszfirstCand7Unique9
		$a_81_1 = {62 61 63 6b 67 72 6f 75 72 64 2e 74 68 65 72 65 31 4d 35 31 38 66 69 72 65 } //1 backgrourd.there1M518fire
		$a_81_2 = {74 68 61 74 50 6e 65 77 } //1 thatPnew
		$a_81_3 = {69 61 6c 6c 6f 77 73 6c 61 74 65 72 } //1 iallowslater
		$a_81_4 = {41 64 62 6c 6f 63 6b 66 65 61 74 75 72 65 73 66 33 36 25 75 34 42 4b 41 } //1 Adblockfeaturesf36%u4BKA
		$a_81_5 = {77 32 6a 63 6f 6e 6e 65 63 74 65 64 64 77 69 74 68 77 33 2c 6f 6e 63 65 } //1 w2jconnecteddwithw3,once
		$a_81_6 = {6d 61 72 6b 47 6f 6f 67 6c 65 5a 6c 6f 67 73 61 } //1 markGoogleZlogsa
		$a_81_7 = {43 68 72 6f 6d 65 63 6f 72 65 6c 65 61 73 65 } //1 Chromecorelease
		$a_81_8 = {44 62 76 76 2e 70 64 62 } //1 Dbvv.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}