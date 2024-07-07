
rule Trojan_BAT_AgentTesla_NAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 6f 90 01 03 0a 7e 90 01 03 04 07 1f 10 5d 91 61 07 20 90 01 03 00 5d d1 61 d1 9d 07 17 58 0b 07 02 6f 90 01 03 0a 32 d4 90 00 } //1
		$a_01_1 = {53 70 6c 69 74 } //1 Split
		$a_01_2 = {43 6f 6e 63 61 74 } //1 Concat
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_NAN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 d0 31 00 00 01 28 90 01 01 00 00 0a 06 17 8d 90 01 01 00 00 01 25 16 d0 90 01 01 00 00 1b 28 90 01 01 00 00 0a a2 28 90 01 01 00 00 0a 14 17 8d 90 01 01 00 00 01 25 16 28 90 01 01 00 00 06 a2 6f 90 01 01 00 00 0a 90 00 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 31 } //1 WindowsFormsApp21
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}