
rule Trojan_Win32_InfoStealer_VW_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 8b 7d 08 33 f8 03 7d 08 33 3d 07 f8 48 00 2b 7d 10 89 7d fc 68 6b f1 48 00 } //10
		$a_01_1 = {6a 01 6a 0c 6a 6f 68 1e f4 48 00 6a 55 6a 5b 68 41 f6 48 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}