
rule TrojanDropper_BAT_VB_N{
	meta:
		description = "TrojanDropper:BAT/VB.N,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 31 73 63 61 6e 74 69 6d 65 5f 63 72 79 70 74 65 72 5f 73 74 75 62 2e 4d 79 } //4 _1scantime_crypter_stub.My
		$a_01_1 = {5f 31 73 63 61 6e 74 69 6d 65 5f 63 72 79 70 74 65 72 5f 73 74 75 62 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //4 _1scantime_crypter_stub.Resources.resources
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}