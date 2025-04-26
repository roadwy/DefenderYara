
rule Trojan_Win32_Fareit_ASP_MTB{
	meta:
		description = "Trojan:Win32/Fareit.ASP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4e 15 b9 94 24 01 46 11 a3 ef d1 14 69 1a a5 84 c7 e6 f7 7e eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}