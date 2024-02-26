
rule Trojan_Win32_Banload_ARA_MTB{
	meta:
		description = "Trojan:Win32/Banload.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 7a 65 70 65 74 74 6f 2e 6f 6e 6c 69 6e 65 2f 61 6f 2f } //02 00  ://zepetto.online/ao/
		$a_01_1 = {44 4c 4c 20 49 6e 6a 65 63 74 65 64 } //02 00  DLL Injected
		$a_01_2 = {50 52 4f 43 45 53 53 20 49 4e 4a 45 43 54 49 4f 4e } //02 00  PROCESS INJECTION
		$a_01_3 = {43 3a 5c 48 57 49 44 2e 74 78 74 } //00 00  C:\HWID.txt
	condition:
		any of ($a_*)
 
}