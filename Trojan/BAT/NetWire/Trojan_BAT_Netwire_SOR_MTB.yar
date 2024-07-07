
rule Trojan_BAT_Netwire_SOR_MTB{
	meta:
		description = "Trojan:BAT/Netwire.SOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {41 75 74 6f 4a 61 63 6b } //1 AutoJack
		$a_81_1 = {49 44 65 66 65 72 72 65 64 } //1 IDeferred
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {5f 5a 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //1 _Z_________________________________________
		$a_81_5 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_81_6 = {41 75 74 6f 4a 61 63 6b 2e 56 69 65 77 2e 45 6e 67 69 6e 65 56 69 65 77 2e 72 65 73 6f 75 72 63 65 73 } //1 AutoJack.View.EngineView.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}