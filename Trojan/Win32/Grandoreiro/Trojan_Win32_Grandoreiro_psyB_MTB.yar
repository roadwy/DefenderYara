
rule Trojan_Win32_Grandoreiro_psyB_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {34 00 73 00 49 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 45 00 41 00 46 00 32 00 54 90 02 05 53 00 33 00 65 00 62 00 4d 00 42 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}