
rule Trojan_MacOS_WireLurker_B_MTB{
	meta:
		description = "Trojan:MacOS/WireLurker.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 65 69 6e 62 61 62 79 2e 63 6f 6d } //01 00  comeinbaby.com
		$a_00_1 = {2f 74 6d 70 2f 73 66 62 61 73 65 2e 64 79 6c 69 62 } //01 00  /tmp/sfbase.dylib
		$a_00_2 = {2f 74 6d 70 2f 73 6d 73 2e 64 62 } //01 00  /tmp/sms.db
		$a_00_3 = {2f 74 6d 70 2f 41 64 64 72 65 73 73 42 6f 6f 6b 2e 73 71 6c 69 74 65 64 62 } //00 00  /tmp/AddressBook.sqlitedb
	condition:
		any of ($a_*)
 
}