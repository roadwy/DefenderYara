
rule Trojan_BAT_Marsilia_KAB_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e9 9a 86 e5 92 8c 00 e5 ae 9d e9 9a 86 e5 92 8c 2e 65 78 65 } //1
		$a_01_1 = {5c 00 53 00 79 00 73 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 64 00 6c 00 6c } //1
		$a_01_2 = {4d 00 79 00 2e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //1 My.Program
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}