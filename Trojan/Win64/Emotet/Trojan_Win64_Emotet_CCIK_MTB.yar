
rule Trojan_Win64_Emotet_CCIK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.CCIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 72 41 31 43 31 61 54 6a 63 54 47 77 4b 74 78 4b 65 5a 59 65 4f 50 54 70 47 49 4a 72 59 36 35 6c 34 4a 30 6b 6a 7a 69 59 45 33 43 4e 53 61 49 4b 52 } //5 ZrA1C1aTjcTGwKtxKeZYeOPTpGIJrY65l4J0kjziYE3CNSaIKR
		$a_01_1 = {4f 7a 65 53 40 2a 2b 62 36 54 78 6f 50 50 21 62 6f 63 63 6e 52 2a 54 } //1 OzeS@*+b6TxoPP!boccnR*T
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}