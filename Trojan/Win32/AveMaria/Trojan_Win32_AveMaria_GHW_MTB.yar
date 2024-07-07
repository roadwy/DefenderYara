
rule Trojan_Win32_AveMaria_GHW_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.GHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 33 d2 f7 f7 8a 84 14 90 01 04 30 04 1e 46 81 fe 90 01 04 7c 90 00 } //10
		$a_01_1 = {56 57 6a 40 68 00 30 00 00 68 00 00 a0 00 6a 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}