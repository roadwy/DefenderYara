
rule Trojan_AndroidOS_SpyAgent_AE{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AE,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 52 45 41 54 45 20 54 41 42 4c 45 20 77 6f 72 6d 5f 73 74 61 74 75 73 20 28 69 64 20 49 4e 54 45 47 45 52 20 50 52 49 4d 41 52 59 20 4b 45 59 20 41 55 54 4f 49 4e 43 52 45 4d 45 4e 54 2c 69 73 5f 61 63 74 69 76 65 20 49 4e 54 45 47 45 52 2c 63 61 6c 6c 5f 74 6f 20 54 45 58 54 2c 66 72 65 71 75 65 6e 63 79 20 49 4e 54 45 47 45 52 2c 64 69 61 6c 6f 67 5f 74 69 74 6c 65 20 54 45 58 54 2c 64 69 61 6c 6f 67 5f 6d 65 73 73 61 67 65 20 54 45 58 54 29 } //2 CREATE TABLE worm_status (id INTEGER PRIMARY KEY AUTOINCREMENT,is_active INTEGER,call_to TEXT,frequency INTEGER,dialog_title TEXT,dialog_message TEXT)
		$a_01_1 = {54 41 42 4c 45 5f 4e 41 4d 45 5f 57 4f 52 4d 53 54 41 54 55 53 } //2 TABLE_NAME_WORMSTATUS
		$a_01_2 = {52 65 67 69 73 74 65 72 57 6f 72 6d 44 61 74 61 } //2 RegisterWormData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}