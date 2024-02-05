
rule Trojan_Win32_SystemBC_psyD_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {45 ec 8b 45 e4 3b 45 f8 73 31 6a 00 8d 45 fc 50 ff 75 ec ff 75 f0 ff 75 e8 ff 15 00 c1 40 00 85 c0 75 04 eb 79 eb 77 8b 45 e4 03 45 fc 89 45 e4 } //00 00 
	condition:
		any of ($a_*)
 
}