
rule Trojan_BAT_PureLog_RDB_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 74 65 79 65 } //1 Goteye
		$a_01_1 = {4d 69 63 72 6f 73 6f 6d 65 73 } //1 Microsomes
		$a_01_2 = {4d 53 47 5f 4e 45 54 } //1 MSG_NET
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}