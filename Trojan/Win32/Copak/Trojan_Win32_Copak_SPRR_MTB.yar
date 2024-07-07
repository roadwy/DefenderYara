
rule Trojan_Win32_Copak_SPRR_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 14 8a 43 00 5b 01 c0 e8 26 00 00 00 41 41 29 c1 31 1e 48 46 81 e8 01 00 00 00 81 e9 01 00 00 00 51 8b 04 24 83 c4 04 39 d6 75 d4 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}