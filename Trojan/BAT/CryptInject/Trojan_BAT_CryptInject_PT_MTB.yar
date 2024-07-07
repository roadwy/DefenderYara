
rule Trojan_BAT_CryptInject_PT_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 32 39 66 66 35 64 63 61 2d 61 65 33 30 2d 34 37 64 62 2d 62 37 34 30 2d 38 66 31 33 30 61 61 31 62 37 35 34 } //1 $29ff5dca-ae30-47db-b740-8f130aa1b754
		$a_81_1 = {54 6f 6b 65 6e 20 53 6f 66 74 77 61 72 65 73 } //1 Token Softwares
		$a_81_2 = {58 33 5f 50 72 6f 66 69 6c 65 5f 4d 61 6e 61 67 65 72 2e 52 6f 63 6b 50 61 70 65 72 53 63 69 73 73 6f 72 73 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 X3_Profile_Manager.RockPaperScissorsForm.resources
		$a_81_3 = {58 33 5f 50 72 6f 66 69 6c 65 5f 4d 61 6e 61 67 65 72 2e 43 6f 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 X3_Profile_Manager.CoinForm.resources
		$a_81_4 = {62 74 6e 54 6f 73 73 } //1 btnToss
		$a_81_5 = {52 6f 63 6b 2c 20 50 61 70 65 72 2c 20 53 63 69 73 73 6f 72 73 } //1 Rock, Paper, Scissors
		$a_81_6 = {51 75 65 20 70 69 6e 67 61 20 65 73 20 65 73 74 6f 21 21 21 } //1 Que pinga es esto!!!
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}