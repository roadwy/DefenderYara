
rule Trojan_Win32_IcedId_DC_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {6b c9 21 89 4d dc 8b 55 e4 83 ea 01 89 55 e4 } //10
		$a_02_1 = {89 82 45 df ff ff 8b 0d 90 01 04 8b 15 90 01 04 8d 84 0a 57 7a 00 00 a3 90 01 04 8b 0d 90 01 04 69 c9 f7 00 00 00 81 f9 45 25 00 00 76 18 8b 15 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}