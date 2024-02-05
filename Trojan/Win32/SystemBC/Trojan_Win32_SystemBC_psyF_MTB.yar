
rule Trojan_Win32_SystemBC_psyF_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {5e 89 f7 b9 00 ee 02 00 eb 32 8a 07 83 c7 01 3c 80 72 0a 3c 8f 77 06 80 7f fe 0f 74 06 2c e8 3c } //00 00 
	condition:
		any of ($a_*)
 
}