
rule Trojan_BAT_SnakeKeylogger_MD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb } //3
		$a_01_1 = {1f 63 20 02 1f 63 20 02 32 7d 36 08 14 90 19 73 19 94 1e bf 20 98 25 e6 20 98 25 f9 21 9a 27 fa 1e 98 24 fe 1e 98 23 ff 1f } //3
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_81_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}