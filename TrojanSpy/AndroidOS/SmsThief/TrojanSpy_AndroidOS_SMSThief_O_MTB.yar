
rule TrojanSpy_AndroidOS_SMSThief_O_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSThief.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6d 73 52 65 63 65 69 76 65 72 } //1 SmsReceiver
		$a_00_1 = {67 65 74 44 69 73 70 6c 61 79 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getDisplayOriginatingAddress
		$a_00_2 = {62 6f 74 5f 69 64 5f 6b 65 79 } //1 bot_id_key
		$a_00_3 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 61 63 74 69 6f 6e 2e 4d 41 49 4e } //1 android.intent.action.MAIN
		$a_00_4 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 63 61 74 65 67 6f 72 79 2e 4c 41 55 4e 43 48 45 52 } //1 android.intent.category.LAUNCHER
		$a_03_5 = {0a 01 38 01 13 00 72 10 ?? ?? 07 00 0c 01 07 14 1f 04 ?? ?? 1a 03 ?? ?? 08 01 14 00 08 02 15 00 76 06 ?? ?? 01 00 28 ea 1a 09 ?? ?? 08 07 14 00 08 08 15 00 07 b1 07 5b 07 c2 07 6c } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*10) >=14
 
}