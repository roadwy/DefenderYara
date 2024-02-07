
rule Trojan_Win32_QHosts_BC{
	meta:
		description = "Trojan:Win32/QHosts.BC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 30 34 5c 90 02 10 2e 76 62 73 00 90 00 } //01 00 
		$a_02_1 = {4c 4f 4b 49 20 3d 22 68 6f 90 02 04 73 90 02 04 74 90 02 04 73 90 00 } //01 00 
		$a_00_2 = {65 63 68 6f 20 25 73 68 73 68 61 25 25 4b 4f 49 4c 25 25 68 75 6c 65 5f 6b 61 6b 25 } //01 00  echo %shsha%%KOIL%%hule_kak%
		$a_00_3 = {25 6b 2e 72 75 } //01 00  %k.ru
		$a_02_4 = {64 72 69 76 65 72 73 22 2b 90 02 04 2b 22 65 74 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}