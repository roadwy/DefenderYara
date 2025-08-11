
rule TrojanSpy_AndroidOS_SpyAgnt_N_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 73 79 62 65 72 69 61 2f 61 6c 70 69 6e 65 71 75 65 73 74 2f 66 75 6c 6c 2f 74 65 6c 65 2f 54 65 6c 65 67 72 61 6d 53 65 72 76 69 63 65 } //1 psyberia/alpinequest/full/tele/TelegramService
		$a_01_1 = {74 70 73 3a 2f 2f 64 65 74 65 63 74 2d 69 6e 66 6f 68 65 6c 70 2e 63 6f 6d 2f 70 61 72 73 65 2f } //1 tps://detect-infohelp.com/parse/
		$a_01_2 = {67 65 74 54 65 6c 65 42 6f 74 55 72 6c } //1 getTeleBotUrl
		$a_01_3 = {73 65 6e 64 44 61 74 61 54 6f 53 72 76 } //1 sendDataToSrv
		$a_01_4 = {70 69 6e 67 54 65 6c 65 } //1 pingTele
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}