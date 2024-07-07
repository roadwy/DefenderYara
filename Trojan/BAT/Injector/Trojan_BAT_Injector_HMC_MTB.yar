
rule Trojan_BAT_Injector_HMC_MTB{
	meta:
		description = "Trojan:BAT/Injector.HMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {69 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f } //1 ioooooooooooooooooooooooo
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_2 = {55 49 75 69 69 75 79 6f 72 65 74 68 75 69 79 74 77 65 75 68 69 77 74 67 65 75 68 69 77 67 72 65 } //1 UIuiiuyorethuiytweuhiwtgeuhiwgre
		$a_81_3 = {41 54 53 57 72 69 74 65 4e 43 50 59 } //1 ATSWriteNCPY
		$a_81_4 = {49 49 55 55 59 49 52 44 52 44 49 55 55 49 } //1 IIUUYIRDRDIUUI
		$a_81_5 = {49 79 74 75 75 79 72 66 65 75 69 6f 79 67 72 66 65 69 75 6f 68 79 67 72 66 65 75 68 69 6f 65 67 72 75 69 68 } //1 Iytuuyrfeuioygrfeiuohygrfeuhioegruih
		$a_81_6 = {58 4f 52 44 65 63 72 79 70 74 } //1 XORDecrypt
		$a_81_7 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}