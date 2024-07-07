
rule TrojanSpy_AndroidOS_SmsThief_BD_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d } //1 /sendMessage?chat_id=
		$a_01_1 = {2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 } //1 /sendDocument
		$a_01_2 = {43 6f 6e 74 61 63 74 73 2e 74 78 74 } //1 Contacts.txt
		$a_01_3 = {73 68 64 2f 73 6b 65 2f 44 65 62 75 67 41 63 74 69 76 69 74 79 } //1 shd/ske/DebugActivity
		$a_01_4 = {2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 /api.telegram.org/bot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}