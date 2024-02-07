
rule Trojan_BAT_AsyncRAT_RDC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {18 5b 2b 41 08 18 6f 25 00 00 0a 1f 10 28 26 00 00 0a 9c 08 18 58 16 2d fb 0c 08 18 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //02 00  GetResponseStream
		$a_01_5 = {2f 00 2f 00 61 00 73 00 65 00 6d 00 63 00 6f 00 73 00 6f 00 6c 00 75 00 63 00 69 00 6f 00 6e 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 } //00 00  //asemcosoluciones.com/loader/uploads/
	condition:
		any of ($a_*)
 
}