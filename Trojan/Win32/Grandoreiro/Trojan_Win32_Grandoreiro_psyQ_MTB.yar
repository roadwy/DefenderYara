
rule Trojan_Win32_Grandoreiro_psyQ_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 09 28 a0 2e 06 57 14 16 9a 26 16 2d f9 fe 09 00 00 28 2b 00 00 0a 2a } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}