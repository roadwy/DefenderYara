
rule Backdoor_Win32_TeviRat_GMD_MTB{
	meta:
		description = "Backdoor:Win32/TeviRat.GMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 98 15 27 01 89 35 bc 10 27 01 8b fe 38 18 74 90 01 01 8b f8 8d 45 f8 50 90 00 } //10
		$a_01_1 = {83 c4 14 48 89 35 a4 10 27 01 5f 5e a3 a0 10 27 01 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}