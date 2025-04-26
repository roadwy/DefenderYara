
rule Trojan_BAT_Heracles_ABVS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ABVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6c 70 50 72 6f 63 65 73 6b 63 61 62 6c 6c 61 43 6e 6f 69 74 61 64 69 6c 61 56 74 72 65 43 65 74 6f 6d 65 52 79 74 69 72 75 63 65 53 74 65 4e 6d 65 74 73 79 53 38 31 36 31 37 } //1 lpProceskcabllaCnoitadilaVtreCetomeRytiruceSteNmetsyS81617
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {48 74 74 70 55 74 69 6c 69 74 79 } //1 HttpUtility
		$a_81_3 = {48 74 74 70 53 65 72 76 65 72 55 74 69 6c 69 74 79 } //1 HttpServerUtility
		$a_81_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_5 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //1 Confuser.Core 1.6.0+447341964f
		$a_81_6 = {53 70 72 61 75 6e 63 79 2e 65 78 65 } //1 Sprauncy.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}