
rule Trojan_Win32_KeyLogger_G_MSR{
	meta:
		description = "Trojan:Win32/KeyLogger.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 48 40 74 4b 65 79 73 48 40 40 6b 2e 44 4c 4c } //01 00 
		$a_01_1 = {48 6f 74 4b 65 79 73 48 6f 6f 6b 43 6c 61 73 73 } //01 00 
		$a_01_2 = {48 6f 74 4b 65 79 73 48 6f 6f 6b 20 53 79 73 74 65 6d 2d 57 69 64 65 20 4d 65 73 73 61 67 65 20 48 6f 6f 6b 20 44 4c 4c } //01 00 
		$a_01_3 = {43 6c 69 65 6e 74 47 65 74 4b 65 79 50 72 6f 63 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}