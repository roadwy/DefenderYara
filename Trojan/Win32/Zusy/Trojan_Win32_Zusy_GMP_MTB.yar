
rule Trojan_Win32_Zusy_GMP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 56 53 ff 15 90 01 04 a1 90 01 01 b0 a5 00 89 35 90 01 01 aa a5 00 8b fe 38 18 90 00 } //10
		$a_03_1 = {8b 45 fc 83 c4 14 48 89 35 90 01 01 aa a5 00 5f 5e a3 90 01 01 a9 a5 00 5b 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}