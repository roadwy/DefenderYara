
rule Trojan_Win32_DelfInject_QR_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.QR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64 } //10
		$a_01_1 = {45 00 4d 00 53 00 49 00 52 00 4f } //3
		$a_81_2 = {52 54 4c 43 6f 6e 73 74 73 } //3 RTLConsts
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}