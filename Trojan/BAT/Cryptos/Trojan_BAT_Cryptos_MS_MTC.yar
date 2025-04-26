
rule Trojan_BAT_Cryptos_MS_MTC{
	meta:
		description = "Trojan:BAT/Cryptos.MS!MTC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {4c 49 4c 4a 41 4a 4d 4b 47 49 48 4d 4d 4f 52 46 } //1 LILJAJMKGIHMMORF
		$a_81_1 = {44 76 45 78 62 7a 46 42 } //1 DvExbzFB
		$a_81_2 = {42 75 74 74 6f 6e 73 61 } //1 Buttonsa
		$a_81_3 = {4e 61 72 66 69 6c 61 6b } //1 Narfilak
		$a_81_4 = {41 73 73 65 6d 62 6c 79 54 72 61 64 65 6d 61 72 6b 41 74 74 72 69 62 75 74 65 } //1 AssemblyTrademarkAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_6 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}