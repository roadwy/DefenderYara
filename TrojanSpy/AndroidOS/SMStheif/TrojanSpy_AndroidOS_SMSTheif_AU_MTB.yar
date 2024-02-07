
rule TrojanSpy_AndroidOS_SMSTheif_AU_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSTheif.AU!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 61 76 65 5f 73 6d 73 2e 70 68 70 3f 66 72 6f 6d 3d } //01 00  /save_sms.php?from=
		$a_01_1 = {61 70 70 2e 61 6d 65 78 2e 65 78 70 72 65 73 73 } //01 00  app.amex.express
		$a_01_2 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //01 00  getOriginatingAddress
		$a_01_3 = {53 6d 73 4c 69 73 74 65 6e 65 72 } //00 00  SmsListener
	condition:
		any of ($a_*)
 
}