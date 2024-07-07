
rule Trojan_Win32_AsyncRAT_MBHL_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.MBHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 00 72 00 5f 00 5f 00 31 00 2d 90 01 04 00 33 00 37 00 37 90 00 } //1
		$a_01_1 = {c4 43 40 00 bf f5 73 01 00 ff ff ff 08 00 00 00 01 00 00 00 19 00 05 00 e9 00 00 00 70 93 40 00 40 9b 40 00 88 28 40 00 78 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}