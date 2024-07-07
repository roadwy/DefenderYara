
rule Trojan_Win32_Amadey_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 39 c1 ef 02 c1 e2 06 8d 54 17 01 8b f8 41 2b fa 8b da c1 ee 05 4e 8a 17 88 10 8a 57 01 88 50 01 83 c0 02 83 c7 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}