
rule Trojan_BAT_Bladabindi_DY_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {61 64 66 61 73 64 61 73 } //1 adfasdas
		$a_01_1 = {43 00 41 00 53 00 48 00 5f 00 43 00 4f 00 55 00 4e 00 54 00 45 00 52 00 5f 00 50 00 41 00 59 00 4d 00 45 00 4e 00 54 00 5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 32 00 34 00 33 00 35 00 } //1 CASH_COUNTER_PAYMENT_ICON_192435
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_3 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //1 ResolveSignature
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_5 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}