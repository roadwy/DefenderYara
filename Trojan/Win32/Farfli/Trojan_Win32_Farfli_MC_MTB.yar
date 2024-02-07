
rule Trojan_Win32_Farfli_MC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 74 24 18 8b 57 54 8b f8 53 8b 4e 3c 03 ca 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4c 24 1c 8b 74 24 14 56 51 8b 51 3c 03 c2 89 03 89 68 34 } //01 00 
		$a_03_1 = {8a 14 08 8b 2f 8b da 81 e3 90 01 04 03 dd 03 f3 81 e6 90 01 04 79 08 4e 81 ce 90 01 04 46 8a 1c 0e 83 c7 04 88 1c 08 40 3d 90 01 04 88 14 0e 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {a9 94 39 11 ed f5 57 42 ed f5 57 42 ed f5 57 42 82 ea 5c 42 e4 f5 57 42 82 ea 5d 42 eb f5 57 42 6e e9 59 42 c1 f5 57 42 96 e9 5b 42 e8 f5 57 42 } //02 00 
		$a_01_1 = {43 6f 6f 6b 69 65 3a 20 25 73 } //02 00  Cookie: %s
		$a_01_2 = {61 6e 6f 6e 79 6d 6f 75 73 40 31 32 33 2e 63 6f 6d } //02 00  anonymous@123.com
		$a_01_3 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  \shell\open\command
		$a_01_4 = {47 65 74 53 63 72 6f 6c 6c 50 6f 73 } //01 00  GetScrollPos
		$a_01_5 = {49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 } //00 00  IsWow64Process
	condition:
		any of ($a_*)
 
}