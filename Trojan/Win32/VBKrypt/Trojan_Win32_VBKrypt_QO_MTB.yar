
rule Trojan_Win32_VBKrypt_QO_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.QO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 04 24 00 57 83 c7 01 5f c1 e7 00 c1 ee 00 83 c7 00 83 c7 00 d9 d0 83 04 24 00 33 3c 24 4a 83 c2 01 c1 ee 00 83 c7 00 f8 83 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}