
rule Trojan_Win32_Azorult_EX_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 74 33 4d 70 89 4d 74 8b 55 6c 2b 55 74 89 55 6c 8b 45 60 2b 45 40 89 45 60 c7 05 90 01 08 90 01 05 b9 90 01 04 6b d1 90 01 01 8b 45 5c 8b 4d 6c 89 0c 10 ba 90 01 04 c1 e2 90 01 01 8b 45 5c 8b 4d 68 89 0c 10 c7 05 90 01 08 c7 05 90 01 08 83 c5 90 01 01 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}