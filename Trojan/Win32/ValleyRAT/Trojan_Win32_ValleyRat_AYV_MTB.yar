
rule Trojan_Win32_ValleyRat_AYV_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.AYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 d4 b9 12 00 00 00 c7 45 e4 4b 00 00 00 be e0 b4 01 10 c7 45 e8 4f 00 00 00 8b f8 f3 a5 83 c4 04 66 a5 a4 c6 40 4b 00 8d 55 d4 c7 45 fc 00 00 00 00 8d 4d c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}