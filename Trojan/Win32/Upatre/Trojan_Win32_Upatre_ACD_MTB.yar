
rule Trojan_Win32_Upatre_ACD_MTB{
	meta:
		description = "Trojan:Win32/Upatre.ACD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 3c 07 8b f7 5f 56 59 58 8b f0 58 83 eb 01 80 f1 f1 c0 c1 04 80 e9 05 80 f1 03 } //10
		$a_01_1 = {8b d0 50 4a 8b fa 03 fe 88 0f 58 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}