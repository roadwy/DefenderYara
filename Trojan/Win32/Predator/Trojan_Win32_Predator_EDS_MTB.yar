
rule Trojan_Win32_Predator_EDS_MTB{
	meta:
		description = "Trojan:Win32/Predator.EDS!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 84 24 04 04 00 00 56 33 f6 85 ff 7e 6f 55 8b 6c 24 08 81 ff 85 02 00 00 } //10
		$a_01_1 = {30 04 33 81 ff 91 05 00 00 75 2e 6a 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}