
rule Trojan_BAT_PureLog_RDB_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 74 65 79 65 } //01 00  Goteye
		$a_01_1 = {4d 69 63 72 6f 73 6f 6d 65 73 } //01 00  Microsomes
		$a_01_2 = {4d 53 47 5f 4e 45 54 } //00 00  MSG_NET
	condition:
		any of ($a_*)
 
}