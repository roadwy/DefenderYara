
rule TrojanSpy_AndroidOS_Zitmo_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Zitmo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 69 6e 6b 41 6e 74 69 76 69 72 75 73 } //1 LinkAntivirus
		$a_00_1 = {41 6e 74 69 76 69 72 75 73 45 6e 61 62 6c 65 64 } //1 AntivirusEnabled
		$a_00_2 = {54 6f 74 61 6c 48 69 64 65 53 6d 73 } //1 TotalHideSms
		$a_00_3 = {4e 45 57 5f 4f 55 54 47 4f 49 4e 47 5f 43 41 4c 4c } //1 NEW_OUTGOING_CALL
		$a_00_4 = {73 6d 73 41 72 65 48 69 64 64 65 6e } //1 smsAreHidden
		$a_00_5 = {4c 63 6f 6d 2f 61 6e 74 69 76 69 72 75 73 2f 6b 61 76 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 Lcom/antivirus/kav/SmsReceiver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}