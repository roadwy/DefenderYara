
rule Trojan_Win32_DelfInject_QG_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.QG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 88 0a c3 0f b7 08 66 89 0a c3 66 8b 08 8a 40 02 66 89 0a 88 42 02 c3 8b 08 89 0a c3 } //10
		$a_01_1 = {45 00 4d 00 53 00 49 00 52 00 4f } //3
		$a_81_2 = {73 79 6e 61 63 6f 64 65 } //3 synacode
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}