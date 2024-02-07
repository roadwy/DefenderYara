
rule Trojan_Win32_Tofumanics_C{
	meta:
		description = "Trojan:Win32/Tofumanics.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 67 20 61 64 64 20 22 68 6b 65 79 5f 6c 6f 63 61 6c 5f 6d 61 63 68 69 6e 65 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e } //01 00  reg add "hkey_local_machine\software\microsoft\windows nt\currentversion\winlogon
		$a_02_1 = {6c 6f 74 75 73 5c 90 02 10 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 6e 6f 74 65 73 5c 90 02 10 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 62 6d 5c 90 00 } //01 00 
		$a_02_2 = {67 65 74 5f 64 6f 77 6e 6c 6f 61 64 5f 69 6e 66 6f 2e 70 68 70 3f 69 64 90 02 10 26 66 6f 72 6d 61 74 3d 90 00 } //01 00 
		$a_02_3 = {72 65 61 64 6d 65 2e 74 78 74 90 02 10 2f 63 20 63 6f 70 79 20 2f 79 20 22 90 00 } //01 00 
		$a_00_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //01 00  netsh firewall set opmode disable
		$a_00_5 = {67 61 74 65 77 61 79 5f 72 65 73 75 6c 74 3d } //00 00  gateway_result=
	condition:
		any of ($a_*)
 
}