
rule Trojan_Win32_Copak_SPGY_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 ca 9f 4c 00 21 c0 01 f0 be 28 ef a9 39 e8 2b 00 00 00 81 c0 b8 0d a0 7a 21 c6 81 ee 53 7e b6 31 31 0a 40 be c4 75 bb 56 29 c0 42 89 c6 81 c6 c4 1c 9e c9 39 fa 75 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}