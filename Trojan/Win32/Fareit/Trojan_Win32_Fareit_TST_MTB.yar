
rule Trojan_Win32_Fareit_TST_MTB{
	meta:
		description = "Trojan:Win32/Fareit.TST!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 c7 96 9d 00 4a f7 c6 79 a1 00 4a f7 c7 41 a4 00 4a f7 c7 29 a8 00 4a f7 c7 89 b2 00 4a f7 c5 f5 b5 00 4a f7 c5 de b9 00 4a f7 c7 bb bc 00 4a } //00 00 
	condition:
		any of ($a_*)
 
}