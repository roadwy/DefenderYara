
rule Trojan_BAT_AsyncRAT_EC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 73 79 6e 63 52 41 54 20 30 2e 34 } //01 00  AsyncRAT 0.4
		$a_81_1 = {64 71 71 69 74 64 61 69 2e 62 30 70 } //01 00  dqqitdai.b0p
		$a_81_2 = {43 6f 6e 6e 65 63 74 65 64 21 } //01 00  Connected!
		$a_81_3 = {49 6e 6a 65 63 74 } //01 00  Inject
		$a_81_4 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } //00 00  /C choice /C Y /N /D Y /T 1 & Del
	condition:
		any of ($a_*)
 
}