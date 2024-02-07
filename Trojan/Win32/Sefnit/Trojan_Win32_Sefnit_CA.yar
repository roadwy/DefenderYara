
rule Trojan_Win32_Sefnit_CA{
	meta:
		description = "Trojan:Win32/Sefnit.CA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 2e 83 65 f8 00 83 65 fc 00 8d 45 f0 50 c7 45 f0 90 01 04 c7 45 f4 90 01 04 ff 15 90 00 } //01 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 44 00 69 00 73 00 63 00 6f 00 76 00 65 00 72 00 79 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //00 00  Windows Network Discovery Service
	condition:
		any of ($a_*)
 
}