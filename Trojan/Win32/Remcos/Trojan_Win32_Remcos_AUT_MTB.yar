
rule Trojan_Win32_Remcos_AUT_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f3 a4 e9 17 03 00 00 81 f9 80 00 00 00 0f 82 ce 01 00 00 57 58 33 c6 a9 0f 90 01 03 75 0e 0f ba 25 90 01 04 01 0f 82 da 04 00 00 0f ba 25 90 01 04 00 0f 83 a7 01 00 00 f7 c7 03 90 01 03 0f 85 b8 01 00 00 f7 c6 03 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}