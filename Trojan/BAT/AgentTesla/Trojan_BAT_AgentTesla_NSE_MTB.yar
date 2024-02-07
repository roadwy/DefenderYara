
rule Trojan_BAT_AgentTesla_NSE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 68 6f 72 74 50 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 72 6f 63 65 73 73 } //01 00  ShortPdddddddddddddddddddrocess
		$a_81_1 = {53 68 6f 72 73 66 73 66 74 50 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 68 66 67 68 67 64 64 64 64 72 6f 63 65 73 73 } //01 00  ShorsfsftPdddddddddddddddhfghgddddrocess
		$a_81_2 = {53 68 6f 72 74 50 64 64 64 64 64 64 64 6a 66 6a 66 64 64 64 64 64 64 64 64 64 64 64 64 72 6f 63 65 73 73 } //01 00  ShortPdddddddjfjfddddddddddddrocess
		$a_81_3 = {53 68 6f 72 74 50 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 66 64 64 64 72 6f 63 65 73 73 } //01 00  ShortPddddddddddddddddfdddrocess
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NSE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 03 00 00 0a 02 03 28 90 01 03 0a 00 03 1c 28 90 01 03 0a 00 03 17 8d 90 01 03 01 0a 06 16 1f 5c 9d 06 6f 90 01 03 0a 03 17 8d 90 01 03 01 0a 06 16 1f 5c 9d 06 6f 90 01 03 0a 8e 69 18 59 9a 1f 16 28 90 01 03 0a 00 03 28 90 01 03 0a 90 00 } //05 00 
		$a_03_1 = {73 0a 00 00 0a 0a 06 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 0a 73 90 01 03 0a 28 90 01 03 0a 73 90 01 03 0a 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 0a 00 06 17 6f 90 01 03 0a 00 06 17 6f 90 01 03 0a 00 06 72 90 01 03 70 90 00 } //01 00 
		$a_01_2 = {73 00 69 00 68 00 6f 00 73 00 74 00 36 00 34 00 } //01 00  sihost64
		$a_01_3 = {46 00 69 00 6c 00 6d 00 6f 00 72 00 61 00 31 00 31 00 43 00 72 00 61 00 63 00 6b 00 } //00 00  Filmora11Crack
	condition:
		any of ($a_*)
 
}