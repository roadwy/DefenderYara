
rule Trojan_Linux_SystemLogWiper_HA{
	meta:
		description = "Trojan:Linux/SystemLogWiper.HA,SIGNATURE_TYPE_ELFHSTR_EXT,14 00 14 00 1b 00 00 02 00 "
		
	strings :
		$a_80_0 = {2f 76 61 72 2f 61 64 6d 2f 6c 61 73 74 6c 6f 67 } ///var/adm/lastlog  02 00 
		$a_80_1 = {2f 76 61 72 2f 61 64 6d 2f 70 61 63 63 74 } ///var/adm/pacct  02 00 
		$a_80_2 = {2f 76 61 72 2f 61 64 6d 2f 75 74 6d 70 } ///var/adm/utmp  02 00 
		$a_80_3 = {2f 76 61 72 2f 61 64 6d 2f 77 74 6d 70 } ///var/adm/wtmp  02 00 
		$a_80_4 = {2f 76 61 72 2f 6c 6f 67 2f 75 74 6d 70 } ///var/log/utmp  02 00 
		$a_80_5 = {2f 76 61 72 2f 6c 6f 67 2f 77 74 6d 70 } ///var/log/wtmp  02 00 
		$a_80_6 = {2f 76 61 72 2f 72 75 6e 2f 75 74 6d 70 } ///var/run/utmp  02 00 
		$a_80_7 = {2f 76 61 72 2f 6c 6f 67 2f 6c 61 73 74 6c 6f 67 } ///var/log/lastlog  12 00 
		$a_80_8 = {41 6c 74 65 72 20 6c 61 73 74 6c 6f 67 20 65 6e 74 72 79 } //Alter lastlog entry  12 00 
		$a_80_9 = {42 6c 61 6e 6b 20 6c 61 73 74 6c 6f 67 20 66 6f 72 20 75 73 65 72 } //Blank lastlog for user  12 00 
		$a_80_10 = {45 72 61 73 65 20 61 63 63 74 20 65 6e 74 72 69 65 73 } //Erase acct entries  12 00 
		$a_80_11 = {45 72 61 73 65 20 6c 61 73 74 20 65 6e 74 72 79 20 66 6f 72 20 75 73 65 72 } //Erase last entry for user  12 00 
		$a_80_12 = {45 72 61 73 65 20 6c 61 73 74 20 65 6e 74 72 79 20 6f 6e 20 74 74 79 } //Erase last entry on tty  12 00 
		$a_80_13 = {45 72 61 73 65 20 61 6c 6c 20 75 73 65 72 6e 61 6d 65 73 } //Erase all usernames  12 00 
		$a_80_14 = {45 72 61 73 65 20 6f 6e 65 20 75 73 65 72 6e 61 6d 65 } //Erase one username  12 00 
		$a_80_15 = {77 69 70 65 5f 61 63 63 74 } //wipe_acct  12 00 
		$a_80_16 = {77 69 70 65 5f 6c 61 73 74 6c 6f 67 } //wipe_lastlog  12 00 
		$a_80_17 = {77 69 70 65 5f 77 74 6d 70 } //wipe_wtmp  12 00 
		$a_80_18 = {77 69 70 65 20 73 79 73 74 65 6d 20 6c 6f 67 73 2e } //wipe system logs.  12 00 
		$a_80_19 = {77 69 70 65 5f 75 74 6d 70 } //wipe_utmp  14 00 
		$a_80_20 = {77 69 70 65 20 61 20 5b 75 73 65 72 6e 61 6d 65 5d } //wipe a [username]  14 00 
		$a_80_21 = {77 69 70 65 20 5b 20 75 7c 77 7c 6c 7c 61 20 5d 20 } //wipe [ u|w|l|a ]   14 00 
		$a_80_22 = {77 69 70 65 20 5b 6c 2c 75 2c 77 5d 20 75 73 65 72 6e 61 6d 65 } //wipe [l,u,w] username  14 00 
		$a_80_23 = {77 69 70 65 20 6c 20 5b 75 73 65 72 6e 61 6d 65 5d } //wipe l [username]  14 00 
		$a_80_24 = {77 69 70 65 20 75 20 5b 75 73 65 72 6e 61 6d 65 5d 20 } //wipe u [username]   14 00 
		$a_80_25 = {77 69 70 65 20 77 20 5b 75 73 65 72 6e 61 6d 65 5d } //wipe w [username]  14 00 
		$a_80_26 = {25 73 20 3c 75 73 65 72 6e 61 6d 65 3e 20 3c 66 69 78 74 68 69 6e 67 73 3e } //%s <username> <fixthings>  00 00 
	condition:
		any of ($a_*)
 
}