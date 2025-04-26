
rule TrojanSpy_AndroidOS_Sandr_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Sandr.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 6e 65 74 2f 64 72 6f 69 64 6a 61 63 6b 2f 73 65 72 76 65 72 2f 43 61 6d 53 6e 61 70 3b } //1 Lnet/droidjack/server/CamSnap;
		$a_00_1 = {53 61 6e 64 72 6f 52 61 74 5f 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 5f 44 61 74 61 62 61 73 65 } //1 SandroRat_BrowserHistory_Database
		$a_00_2 = {2f 57 68 61 74 73 41 70 70 2f 44 61 74 61 62 61 73 65 73 2f 77 61 6d 73 2e 64 62 } //1 /WhatsApp/Databases/wams.db
		$a_00_3 = {49 4e 54 45 52 43 45 50 54 5f 49 4e 43 4f 4d 49 4e 47 5f 53 4d 53 5f 4e 4f 53 } //1 INTERCEPT_INCOMING_SMS_NOS
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}