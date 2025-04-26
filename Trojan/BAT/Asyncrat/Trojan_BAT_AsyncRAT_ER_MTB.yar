
rule Trojan_BAT_AsyncRAT_ER_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 1f 0c 11 07 1f 0c 95 08 1f 0c 95 61 9e 11 07 1f 0d 11 07 1f 0d 95 08 1f 0d 95 61 9e 11 07 1f 0e 11 07 1f 0e 95 08 1f 0e 95 61 9e 11 07 1f 0f 11 07 1f 0f 95 08 1f 0f 95 61 } //5
		$a_01_1 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 58 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}