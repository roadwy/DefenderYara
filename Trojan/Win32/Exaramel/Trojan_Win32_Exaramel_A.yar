
rule Trojan_Win32_Exaramel_A{
	meta:
		description = "Trojan:Win32/Exaramel.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 73 00 6d 00 70 00 72 00 6f 00 76 00 61 00 76 00 2e 00 65 00 78 00 65 00 } //01 00  wsmprovav.exe
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 43 00 68 00 65 00 63 00 6b 00 20 00 41 00 56 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00  Windows Check AV service
		$a_01_2 = {2f 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2f 00 70 00 72 00 6f 00 78 00 79 00 2f 00 40 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //01 00  /settings/proxy/@password
		$a_01_3 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //00 00  SYSTEM\CurrentControlSet\Services
	condition:
		any of ($a_*)
 
}