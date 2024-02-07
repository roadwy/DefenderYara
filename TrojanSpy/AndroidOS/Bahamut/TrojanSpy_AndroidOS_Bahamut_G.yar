
rule TrojanSpy_AndroidOS_Bahamut_G{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {24 63 61 6c 6c 4c 6f 67 44 61 6f } //01 00  $callLogDao
		$a_00_1 = {24 73 6d 73 44 61 6f } //01 00  $smsDao
		$a_00_2 = {24 76 69 62 65 72 44 61 6f } //01 00  $viberDao
		$a_00_3 = {24 69 6d 6f 44 61 6f } //01 00  $imoDao
		$a_00_4 = {24 70 72 6f 74 65 63 74 65 64 44 61 6f } //01 00  $protectedDao
		$a_00_5 = {24 73 69 67 6e 61 6c 44 61 6f } //00 00  $signalDao
	condition:
		any of ($a_*)
 
}