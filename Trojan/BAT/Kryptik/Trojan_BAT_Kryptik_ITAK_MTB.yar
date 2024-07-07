
rule Trojan_BAT_Kryptik_ITAK_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ITAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {42 65 66 4b 6f 6e 69 6e 67 } //1 BefKoning
		$a_01_1 = {47 61 73 4a 65 77 73 } //1 GasJews
		$a_01_2 = {47 65 74 54 68 65 4a 65 77 73 } //1 GetTheJews
		$a_01_3 = {53 74 61 72 74 48 75 6d 61 6e 45 78 70 65 72 69 6d 65 6e 74 } //1 StartHumanExperiment
		$a_01_4 = {53 74 61 72 74 48 75 6d 61 6e 45 78 70 65 72 69 6d 65 6e 74 44 6f 75 62 6c 65 44 6f 77 6e } //1 StartHumanExperimentDoubleDown
		$a_01_5 = {53 74 61 72 74 4e 75 72 6e 62 65 72 67 50 72 6f 63 65 73 73 } //1 StartNurnbergProcess
		$a_01_6 = {53 46 63 65 6b 4e 61 69 41 74 42 4e 51 4e 65 4f 44 58 47 6f 79 } //1 SFcekNaiAtBNQNeODXGoy
		$a_01_7 = {49 4a 4f 4a 62 79 4d 54 74 75 45 58 74 41 75 69 49 79 55 } //1 IJOJbyMTtuEXtAuiIyU
		$a_01_8 = {62 4d 77 50 61 42 46 71 62 6f 52 4d 75 52 6f 4e 63 63 } //1 bMwPaBFqboRMuRoNcc
		$a_01_9 = {69 51 54 69 64 66 71 74 49 77 4e 43 65 69 71 4b 4e 56 41 79 71 5a 6e } //1 iQTidfqtIwNCeiqKNVAyqZn
		$a_01_10 = {69 77 7a 78 41 6e 6e 45 6f 62 43 49 58 64 68 6b 51 } //1 iwzxAnnEobCIXdhkQ
		$a_01_11 = {6f 48 67 49 42 41 7a 48 41 54 42 44 64 44 74 44 } //1 oHgIBAzHATBDdDtD
		$a_01_12 = {78 4e 73 77 7a 4f 49 65 70 64 41 46 55 43 6a 47 45 4a 44 6e 4b 53 } //1 xNswzOIepdAFUCjGEJDnKS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}