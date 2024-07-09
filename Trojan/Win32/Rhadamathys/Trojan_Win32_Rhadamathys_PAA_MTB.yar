
rule Trojan_Win32_Rhadamathys_PAA_MTB{
	meta:
		description = "Trojan:Win32/Rhadamathys.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 3c 24 89 54 24 ?? 89 da c1 e2 ?? 03 54 24 ?? 8d 3c 33 31 d7 89 da c1 ea ?? 01 ea 31 fa 29 d0 89 c2 c1 e2 ?? 03 14 24 8d 3c 06 31 d7 89 c2 c1 ea ?? 03 54 24 ?? 31 fa 29 d3 81 c6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}