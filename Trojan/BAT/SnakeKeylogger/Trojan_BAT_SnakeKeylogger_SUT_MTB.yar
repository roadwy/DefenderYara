
rule Trojan_BAT_SnakeKeylogger_SUT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_1 = {49 41 73 79 6e 63 52 65 73 75 6c 74 } //1 IAsyncResult
		$a_00_2 = {06 07 a3 02 00 00 01 28 05 00 00 06 dd 06 00 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}