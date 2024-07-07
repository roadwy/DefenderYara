
rule Trojan_Win32_Azorult_RRI_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RRI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 00 00 00 00 81 2c 24 52 ef 6f 62 b8 41 e5 64 03 81 2c 24 68 19 2a 14 81 04 24 be 08 9a 76 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}