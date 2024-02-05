
rule Trojan_Win32_Grandoreiro_psyC_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {76 34 2e 30 2e 33 30 33 31 39 00 00 00 00 05 00 6c 00 00 00 64 03 00 00 23 7e 00 00 d0 03 00 00 fc 03 00 00 23 53 74 72 69 6e 67 73 00 00 00 00 cc 07 00 00 e4 } //00 00 
	condition:
		any of ($a_*)
 
}