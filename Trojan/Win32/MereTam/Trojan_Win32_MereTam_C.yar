
rule Trojan_Win32_MereTam_C{
	meta:
		description = "Trojan:Win32/MereTam.C,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 ee 08 8b da 8b ce d3 fb 83 c7 01 85 f6 88 5c 07 ff 75 ec 8b 4c 24 18 83 c5 04 83 e9 01 89 4c 24 18 0f 85 90 01 01 fe ff ff 90 00 } //01 00 
		$a_00_1 = {83 ee 08 8b da 8b ce d3 fb 47 85 f6 88 5c 07 ff 75 ee 8b 4c 24 18 83 c5 04 49 89 4c 24 18 0f 85 4a fe ff ff } //0a 00 
		$a_00_2 = {56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00 } //0a 00 
		$a_00_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //0a 00  C:\ProgramData\
		$a_00_4 = {25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 25 73 } //00 00  %s\shell\open\%s
		$a_00_5 = {5d 04 00 00 ae ef 03 80 5c 1e 00 00 af ef 03 80 00 00 01 00 08 00 08 00 ac 21 55 70 61 74 } //72 65 
	condition:
		any of ($a_*)
 
}