
rule Trojan_Win32_Raccooon_RI_MTB{
	meta:
		description = "Trojan:Win32/Raccooon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 89 54 24 08 89 0c 24 c7 44 24 04 00 00 00 00 8b 44 24 08 01 44 24 04 8b 44 24 04 31 04 24 8b 04 24 83 c4 0c c3 90 02 10 81 01 e1 34 ef c6 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}