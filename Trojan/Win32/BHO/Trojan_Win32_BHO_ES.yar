
rule Trojan_Win32_BHO_ES{
	meta:
		description = "Trojan:Win32/BHO.ES,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {49 73 49 65 4f 70 65 6e 00 90 01 23 49 73 44 65 6c 4d 79 53 65 6c 66 00 53 65 72 76 65 72 55 72 6c 90 00 } //02 00 
		$a_00_1 = {73 61 66 65 6d 6f 6e 2e 64 6c 6c } //01 00  safemon.dll
		$a_00_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 25 73 } //01 00  taskkill /F /IM %s
		$a_00_3 = {25 73 3f 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 } //00 00  %s?user=%s&pass=%s&
	condition:
		any of ($a_*)
 
}