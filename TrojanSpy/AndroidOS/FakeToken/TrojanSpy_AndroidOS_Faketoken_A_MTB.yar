
rule TrojanSpy_AndroidOS_Faketoken_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Faketoken.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 4d 79 20 43 6d 64 2e 43 68 61 6e 67 65 53 65 72 76 65 72 2e 43 4f 4d 4d 41 4e 44 20 6e 65 77 20 73 65 72 76 65 72 3a } //01 00  ServMy Cmd.ChangeServer.COMMAND new server:
		$a_00_1 = {73 65 72 76 65 72 20 54 45 58 54 2c 20 69 6e 74 65 72 63 65 70 74 20 54 45 58 54 2c 20 69 73 5f 64 69 76 69 63 65 5f 61 64 6d 69 6e 20 49 4e 54 45 47 45 52 2c 20 74 65 78 74 5f 69 6e 66 6f 20 54 45 58 54 2c 20 73 63 68 65 63 6b 5f 64 65 6c 5f 6d 73 67 20 49 4e 54 45 47 45 52 } //01 00  server TEXT, intercept TEXT, is_divice_admin INTEGER, text_info TEXT, scheck_del_msg INTEGER
		$a_00_2 = {53 6d 73 52 65 63 65 69 76 65 72 20 6f 6e 52 65 63 65 69 76 65 20 73 65 74 53 69 6c 65 6e 74 4d 6f 64 65 } //01 00  SmsReceiver onReceive setSilentMode
		$a_00_3 = {67 65 74 42 6c 6f 63 6b 53 6d 73 54 69 6d 65 } //00 00  getBlockSmsTime
	condition:
		any of ($a_*)
 
}