
rule Trojan_AndroidOS_Brata_A{
	meta:
		description = "Trojan:AndroidOS/Brata.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 11 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 77 73 68 5f 63 6f 6e 6e 65 63 74 74 6f 79 6f 75 } //01 00  _wsh_connecttoyou
		$a_00_1 = {5f 77 73 68 5f 73 65 74 6b 65 79 6c 6f 67 61 70 70 } //01 00  _wsh_setkeylogapp
		$a_00_2 = {5f 77 73 68 5f 6c 6f 61 64 6b 65 79 6c 6f 67 64 61 74 61 } //01 00  _wsh_loadkeylogdata
		$a_00_3 = {5f 77 73 68 5f 73 65 6e 64 63 6c 69 63 6b 73 } //01 00  _wsh_sendclicks
		$a_00_4 = {5f 77 73 68 5f 6f 70 65 6e 61 70 70 } //01 00  _wsh_openapp
		$a_00_5 = {5f 77 73 68 5f 64 69 73 63 6f 6e 6e 65 63 74 65 64 66 72 6f 6d 61 64 6d 69 6e } //01 00  _wsh_disconnectedfromadmin
		$a_00_6 = {5f 77 73 68 5f 6f 70 65 6e 72 65 63 65 6e 74 73 61 70 70 73 } //01 00  _wsh_openrecentsapps
		$a_00_7 = {5f 77 73 68 5f 66 6f 72 6d 61 74 74 68 69 73 64 65 76 69 63 65 } //01 00  _wsh_formatthisdevice
		$a_00_8 = {5f 77 73 68 5f 73 65 6e 64 73 63 74 6f 6d 65 } //01 00  _wsh_sendsctome
		$a_00_9 = {5f 77 73 68 5f 63 6c 69 63 6b 6f 6e 61 64 64 6c 6f 63 6b } //01 00  _wsh_clickonaddlock
		$a_00_10 = {5f 77 73 68 5f 73 74 61 72 74 73 63 72 6f 6c 6c } //01 00  _wsh_startscroll
		$a_00_11 = {5f 77 73 68 5f 75 6e 69 6e 73 74 61 6c 6c 61 70 70 } //01 00  _wsh_uninstallapp
		$a_00_12 = {5f 77 73 68 5f 73 65 6e 64 73 6d 73 6d 65 73 73 61 67 65 73 } //01 00  _wsh_sendsmsmessages
		$a_00_13 = {5f 77 73 68 5f 77 61 6b 65 75 70 70 68 6f 6e 65 } //01 00  _wsh_wakeupphone
		$a_00_14 = {5f 77 73 68 5f 73 65 6e 64 73 6d 73 6d 65 73 73 61 67 65 73 74 6f 6e 75 6d 62 65 72 } //01 00  _wsh_sendsmsmessagestonumber
		$a_00_15 = {5f 73 65 6e 64 5f 73 6f 63 6b 65 74 5f 64 61 74 61 } //01 00  _send_socket_data
		$a_00_16 = {5f 6c 6f 61 64 5f 61 6c 6c 61 70 70 73 64 61 74 61 } //00 00  _load_allappsdata
	condition:
		any of ($a_*)
 
}