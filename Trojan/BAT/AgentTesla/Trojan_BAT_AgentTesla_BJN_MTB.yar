
rule Trojan_BAT_AgentTesla_BJN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 0d 06 14 20 90 01 04 28 90 01 03 06 17 8d 90 01 03 01 25 16 06 14 20 90 01 04 28 90 01 03 06 16 8d 90 01 03 01 14 14 14 28 90 01 03 0a 1b 8c 90 01 03 01 28 90 01 03 0a a2 14 14 28 90 01 03 0a 06 14 20 90 01 04 28 90 01 03 06 19 8d 90 01 03 01 25 16 09 a2 25 17 16 8c 90 01 03 01 a2 25 18 1a 8c 90 00 } //01 00 
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //01 00  InvokeMethod
		$a_81_2 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //00 00  GZipStream
	condition:
		any of ($a_*)
 
}