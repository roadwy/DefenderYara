
rule TrojanDropper_BAT_Drogcatchaft_A{
	meta:
		description = "TrojanDropper:BAT/Drogcatchaft.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 5f 47 6f 64 66 61 74 68 65 72 5f 53 74 75 62 2e 46 6f 72 6d } //5 The_Godfather_Stub.Form
		$a_01_1 = {45 00 64 00 31 00 48 00 33 00 72 00 30 00 } //1 Ed1H3r0
		$a_01_2 = {5c 00 43 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 \Crypted.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}