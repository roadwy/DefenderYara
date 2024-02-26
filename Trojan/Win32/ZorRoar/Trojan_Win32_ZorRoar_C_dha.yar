
rule Trojan_Win32_ZorRoar_C_dha{
	meta:
		description = "Trojan:Win32/ZorRoar.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 01 ffffff90 01 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {47 00 65 00 74 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 20 00 69 00 6e 00 66 00 6f 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 } //64 00  Get installed applications info failed
		$a_01_1 = {47 00 65 00 74 00 20 00 69 00 6e 00 66 00 6f 00 20 00 65 00 72 00 72 00 6f 00 72 00 3a 00 20 00 6f 00 70 00 65 00 6e 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 } //64 00  Get info error: open registry
		$a_01_2 = {43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 6e 00 61 00 6d 00 65 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 } //64 00  Computer name failed
		$a_01_3 = {55 00 73 00 65 00 72 00 20 00 6e 00 61 00 6d 00 65 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 } //00 00  User name failed
	condition:
		any of ($a_*)
 
}