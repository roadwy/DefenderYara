
rule Trojan_Win64_InfoStealer_NI_MTB{
	meta:
		description = "Trojan:Win64/InfoStealer.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8d 15 ea 19 04 00 48 89 0c 24 44 0f 11 7c 24 08 48 89 54 24 18 48 89 44 24 20 44 0f 11 7c 24 28 e8 ?? ?? ?? ?? 45 0f 57 ff 4c 8b 35 00 50 9d 00 } //3
		$a_01_1 = {70 6f 72 74 67 65 74 61 64 64 72 69 6e 66 6f 77 74 72 61 6e 73 6d 69 74 66 69 6c 65 } //1 portgetaddrinfowtransmitfile
		$a_01_2 = {42 69 74 61 70 70 43 6f 69 6e } //1 BitappCoin
		$a_01_3 = {6d 61 73 74 65 72 6b 65 79 5f 64 62 } //1 masterkey_db
		$a_01_4 = {46 72 6f 6d 69 63 6d 70 69 67 6d 70 66 74 70 73 70 6f 70 33 73 6d 74 70 64 69 61 6c } //1 Fromicmpigmpftpspop3smtpdial
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}