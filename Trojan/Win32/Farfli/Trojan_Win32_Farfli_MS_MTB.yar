
rule Trojan_Win32_Farfli_MS_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 66 77 75 2e 33 33 32 32 2e 6f 72 67 } //01 00 
		$a_01_1 = {53 63 72 6f 6c 6c } //01 00 
		$a_01_2 = {4e 75 6d 20 4c 6f 63 6b } //01 00 
		$a_01_3 = {49 6e 73 65 72 74 } //01 00 
		$a_01_4 = {53 6e 61 70 73 68 6f 74 } //01 00 
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 2e 33 38 36 } //01 00 
		$a_03_6 = {8d 95 6c ff ff ff 52 6a 00 68 03 00 1f 00 ff 15 90 01 04 8b f0 85 f6 75 90 01 01 68 c8 00 00 00 ff 15 90 01 04 47 81 ff e8 03 00 00 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}