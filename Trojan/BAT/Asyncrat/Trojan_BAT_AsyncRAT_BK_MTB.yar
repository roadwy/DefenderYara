
rule Trojan_BAT_AsyncRAT_BK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 95 b6 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 8d 00 00 00 4d 00 00 00 bb 00 00 00 ea 02 } //4
		$a_01_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //2 GetManifestResourceStream
		$a_01_2 = {52 65 76 65 72 73 65 } //2 Reverse
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=8
 
}