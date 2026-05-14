
rule Trojan_BAT_Crysan_MKA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8c 00 ffffff8c 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 41 6e 61 6c 79 73 69 73 } //35 AntiAnalysis
		$a_01_1 = {41 64 76 61 6e 63 65 64 43 72 79 70 74 6f } //30 AdvancedCrypto
		$a_01_2 = {53 74 65 61 6c 74 68 45 78 65 63 75 74 6f 72 } //25 StealthExecutor
		$a_01_3 = {45 78 65 63 75 74 65 53 74 65 61 6c 74 68 } //20 ExecuteStealth
		$a_01_4 = {70 61 79 6c 6f 61 64 } //15 payload
		$a_01_5 = {4d 75 6c 74 69 4c 61 79 65 72 44 65 63 72 79 70 74 } //10 MultiLayerDecrypt
		$a_81_6 = {73 61 6e 64 62 6f 78 } //5 sandbox
	condition:
		((#a_01_0  & 1)*35+(#a_01_1  & 1)*30+(#a_01_2  & 1)*25+(#a_01_3  & 1)*20+(#a_01_4  & 1)*15+(#a_01_5  & 1)*10+(#a_81_6  & 1)*5) >=140
 
}