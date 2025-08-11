
rule Trojan_Win32_Fragtor_KK_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 ad c0 14 83 c0 04 eb 0b dd 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 ea 01 f9 72 } //8
		$a_03_1 = {83 2f 01 f9 72 0b 2f e3 ?? 09 c0 4b 8a 5b af 0c d7 } //7
		$a_01_2 = {46 65 33 30 34 38 31 32 34 38 33 32 66 30 63 65 66 38 38 33 39 34 31 65 36 30 33 35 65 32 62 62 62 63 32 33 37 2e 65 78 65 46 65 } //5 Fe3048124832f0cef883941e6035e2bbbc237.exeFe
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*7+(#a_01_2  & 1)*5) >=20
 
}