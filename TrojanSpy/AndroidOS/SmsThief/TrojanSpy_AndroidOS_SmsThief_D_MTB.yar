
rule TrojanSpy_AndroidOS_SmsThief_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 69 6e 67 20 74 65 78 74 53 6d 73 20 74 6f 20 62 65 20 73 65 6e 64 20 21 } //01 00  Creating textSms to be send !
		$a_00_1 = {77 65 62 2e 6d 65 2e 63 6f 6d } //01 00  web.me.com
		$a_00_2 = {53 65 6e 64 20 43 61 6c 6c 73 20 6c 6f 67 } //01 00  Send Calls log
		$a_00_3 = {63 68 65 63 6b 45 6d 61 69 6c 53 6d 73 } //01 00  checkEmailSms
		$a_00_4 = {50 68 6f 6e 65 4c 6f 63 61 74 6f 72 2f 50 72 6f 5f 76 65 72 73 69 6f 6e } //00 00  PhoneLocator/Pro_version
		$a_00_5 = {be b9 00 00 } //05 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_SmsThief_D_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 48 52 30 63 44 6f 76 4c 32 46 77 61 58 4e 6c 63 6e 5a 6c 63 69 35 36 65 6d 5a 35 63 43 35 6a 62 32 30 36 4d 6a 41 35 4e 53 39 68 63 47 6b 3d } //02 00  aHR0cDovL2FwaXNlcnZlci56emZ5cC5jb206MjA5NS9hcGk=
		$a_00_1 = {4c 63 6f 6d 2f 6b 62 35 33 34 2f 65 6b 73 74 76 6e 2f 6e 65 74 2f 65 6e 74 69 74 79 2f 43 61 6c 6c 4c 6f 67 45 6e 74 69 74 79 3b } //01 00  Lcom/kb534/ekstvn/net/entity/CallLogEntity;
		$a_00_2 = {3f 74 79 70 65 3d 69 6e 63 6f 6d 69 6e 67 4f 6e 43 61 6c 6c } //01 00  ?type=incomingOnCall
		$a_00_3 = {2f 41 6e 64 72 6f 69 64 2f 53 6d 61 2f 4c 6f 67 } //01 00  /Android/Sma/Log
		$a_00_4 = {67 65 74 53 6d 73 54 79 70 65 } //01 00  getSmsType
		$a_00_5 = {67 65 74 53 61 6c 65 72 5f 63 6f 64 65 } //00 00  getSaler_code
		$a_00_6 = {5d 04 00 00 } //0d 56 
	condition:
		any of ($a_*)
 
}