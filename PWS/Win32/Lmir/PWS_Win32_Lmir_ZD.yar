
rule PWS_Win32_Lmir_ZD{
	meta:
		description = "PWS:Win32/Lmir.ZD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 69 72 31 2e 64 61 74 } //01 00 
		$a_00_1 = {45 6e 64 48 6f 6f 6b 00 47 65 74 49 6e 73 74 53 6f 75 46 69 6c 65 00 47 65 74 54 72 56 65 72 73 69 6f 6e 00 53 65 74 49 6e 69 74 53 74 61 74 65 00 53 65 74 49 6e 73 74 53 6f 75 46 69 6c 65 00 53 74 61 72 74 48 6f 6f 6b 00 53 74 61 72 74 4c 69 73 74 65 6e 00 } //01 00 
		$a_02_2 = {81 ec 04 01 00 00 80 a5 fc fe ff ff 00 53 56 57 6a 40 33 c0 59 8d bd fd fe ff ff f3 ab 66 ab 68 90 01 04 68 90 01 04 aa ff 15 90 01 04 8b d8 8d 85 fc fe ff ff 68 04 01 00 00 50 6a 00 ff 15 90 01 04 8d 85 fc fe ff ff 6a 5c 50 ff 15 90 01 04 8b 3d 90 01 04 8b f0 46 68 90 01 04 56 ff d7 83 c4 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}