
rule Trojan_Win32_Ulise_GMX_MTB{
	meta:
		description = "Trojan:Win32/Ulise.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 d8 c1 e0 05 8b 55 fc 8b 54 02 14 51 29 d1 8a 02 88 04 11 83 c2 01 84 c0 75 } //10
		$a_01_1 = {2e 65 64 6c 77 76 } //1 .edlwv
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}