
rule Trojan_Win32_LummaStealer_DU_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5c 24 1c 89 da f7 d2 89 d1 81 e1 fa 00 00 00 89 d8 83 e0 05 01 c0 81 ca fa 00 00 00 01 da 83 c2 06 29 d8 05 fa 00 00 00 21 d0 29 c8 88 44 2c 18 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}