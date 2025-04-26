
rule Trojan_Win64_Grandoreiro_psyD_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 64 24 00 8a 08 40 84 c9 75 f9 2b c2 53 56 8b d0 b8 70 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}