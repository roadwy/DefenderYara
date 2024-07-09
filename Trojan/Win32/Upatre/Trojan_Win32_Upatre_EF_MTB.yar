
rule Trojan_Win32_Upatre_EF_MTB{
	meta:
		description = "Trojan:Win32/Upatre.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 06 33 c1 90 18 8b c8 88 07 83 c6 01 c3 } //10
		$a_00_1 = {8b 4f ff 8a cd eb d9 47 4b 8b c3 c3 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}