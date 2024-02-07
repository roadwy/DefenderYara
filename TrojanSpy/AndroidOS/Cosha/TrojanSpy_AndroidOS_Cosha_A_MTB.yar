
rule TrojanSpy_AndroidOS_Cosha_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Cosha.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 61 6e 78 69 6e 33 36 30 2e 63 6f 6d 2f 77 65 6c 63 6f 6d 65 2f 70 2e 61 73 68 78 3f 6c 61 74 3d } //01 00  www.anxin360.com/welcome/p.ashx?lat=
		$a_01_1 = {53 65 6e 64 53 4d 53 } //01 00  SendSMS
		$a_01_2 = {53 4d 53 53 72 76 } //01 00  SMSSrv
		$a_01_3 = {56 34 53 4d 53 53 65 72 76 } //00 00  V4SMSServ
	condition:
		any of ($a_*)
 
}