
rule Trojan_Win32_Raccoon_MP_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 25 00 8b 4d 04 81 c5 08 00 00 00 3b ed f9 89 08 81 ef 04 00 00 00 c0 d4 7d 8b 07 33 c3 85 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}