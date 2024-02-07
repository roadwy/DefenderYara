
rule Trojan_Win32_Fareit_RM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {69 4f 25 57 4c 31 6e 4e 2a 58 4c 37 6b 46 31 73 42 31 71 52 31 57 45 48 65 46 43 6d 4a 39 70 4a 43 } //01 00  iO%WL1nN*XL7kF1sB1qR1WEHeFCmJ9pJC
		$a_81_1 = {46 61 6b 65 20 43 6f 6e 6e 65 63 74 73 } //01 00  Fake Connects
		$a_81_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 73 6e 62 63 2e 63 6f 6d 2f 77 69 7a 2f } //01 00  http://www.ssnbc.com/wiz/
		$a_81_3 = {50 61 73 73 77 6f 72 64 53 74 72 } //01 00  PasswordStr
		$a_81_4 = {50 61 79 4c 6f 61 64 } //01 00  PayLoad
		$a_81_5 = {50 72 6f 63 49 6e 6a 65 63 74 } //00 00  ProcInject
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 6c 65 72 74 61 6c 73 62 65 73 6c 75 74 6e 69 6e 67 65 6e 73 } //02 00  Flertalsbeslutningens
		$a_01_1 = {47 72 75 6e 64 66 75 6e 6b 74 69 6f 6e 65 72 6e 65 73 } //01 00  Grundfunktionernes
		$a_00_2 = {75 00 64 00 73 00 6b 00 72 00 69 00 66 00 74 00 73 00 62 00 65 00 74 00 69 00 6e 00 67 00 65 00 6c 00 73 00 65 00 6e 00 73 00 } //02 00  udskriftsbetingelsens
		$a_01_3 = {76 69 72 6b 73 6f 6d 68 65 64 73 6c 65 64 65 72 65 6e 73 } //02 00  virksomhedslederens
		$a_00_4 = {53 00 65 00 69 00 73 00 6d 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 6e 00 73 00 37 00 } //01 00  Seismologiens7
		$a_01_5 = {45 70 6f 78 79 6d 61 6c 69 6e 67 65 72 34 } //00 00  Epoxymalinger4
	condition:
		any of ($a_*)
 
}