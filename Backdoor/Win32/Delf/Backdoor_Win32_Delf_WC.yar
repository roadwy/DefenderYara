
rule Backdoor_Win32_Delf_WC{
	meta:
		description = "Backdoor:Win32/Delf.WC,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 45 ec 50 e8 90 01 02 ff ff c6 85 90 01 01 fe ff ff 55 c6 85 90 01 01 fe ff ff 50 c6 85 90 01 01 fe ff ff 58 c6 85 90 01 01 fe ff ff 32 c6 85 90 01 01 fe ff ff 00 c6 85 90 01 01 fe ff ff 00 c6 85 90 01 01 fe ff ff 00 c6 85 90 01 01 fe ff ff 00 8b 85 90 01 01 ff ff ff 89 85 90 01 01 fe ff ff c7 85 90 01 01 fe ff ff 00 04 00 00 c7 85 90 01 01 fe ff ff 00 04 00 00 8b 85 90 01 01 fe ff ff 03 85 90 01 01 fe ff ff 89 85 90 01 01 fe ff ff c7 85 90 01 01 fe ff ff 20 00 00 e6 90 00 } //0a 00 
		$a_02_1 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 90 02 80 44 65 73 63 72 69 70 74 69 6f 6e 90 02 80 5c 50 61 72 61 6d 65 74 65 72 73 90 02 80 53 65 72 76 69 63 65 44 6c 6c 90 00 } //05 00 
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //05 00 
		$a_00_3 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //00 00 
	condition:
		any of ($a_*)
 
}