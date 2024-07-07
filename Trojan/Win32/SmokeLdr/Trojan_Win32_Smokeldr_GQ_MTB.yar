
rule Trojan_Win32_Smokeldr_GQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeldr.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 36 23 01 00 01 45 90 01 01 8b 0d 90 01 04 03 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 8a 02 88 01 8b e5 5d c2 90 00 } //10
		$a_02_1 = {c1 e9 05 89 4d 90 01 01 8b 55 90 01 01 52 8d 45 90 01 01 50 90 02 05 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}