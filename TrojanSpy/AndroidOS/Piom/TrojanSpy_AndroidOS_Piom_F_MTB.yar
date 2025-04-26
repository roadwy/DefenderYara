
rule TrojanSpy_AndroidOS_Piom_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Piom.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6e 65 6f 6e 65 74 2f 61 70 70 2f 72 65 61 64 65 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/neonet/app/reader/MainActivity
		$a_01_1 = {63 6f 6d 2e 73 6d 6f 64 6a 2e 61 70 70 2e 73 6d 73 74 6f 74 65 6c 65 67 72 61 6d } //1 com.smodj.app.smstotelegram
		$a_01_2 = {76 65 72 69 66 69 63 61 72 50 65 72 6d 69 73 6f 73 } //1 verificarPermisos
		$a_01_3 = {73 65 74 57 65 62 56 69 65 77 43 6c 69 65 6e 74 } //1 setWebViewClient
		$a_01_4 = {75 6e 73 65 6e 74 4d 73 67 } //1 unsentMsg
		$a_01_5 = {73 65 6e 64 54 6f 54 65 6c 65 67 72 61 6d 41 50 49 } //1 sendToTelegramAPI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}