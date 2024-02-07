
rule Trojan_Win32_Adload_A{
	meta:
		description = "Trojan:Win32/Adload.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 64 4b 20 64 6f 77 6e 6c 6f 61 64 65 64 } //01 00  %dK downloaded
		$a_01_1 = {63 73 5f 42 61 6e 6e 65 72 3a 20 25 73 } //01 00  cs_Banner: %s
		$a_01_2 = {43 6f 6f 6b 69 65 3a 20 50 57 5f 31 2e 30 3d } //01 00  Cookie: PW_1.0=
		$a_01_3 = {4d 61 72 6b 65 74 65 72 55 49 44 3a 20 25 73 } //01 00  MarketerUID: %s
		$a_01_4 = {5c 6d 61 73 74 65 72 5f 69 64 78 2e 64 74 6d } //01 00  \master_idx.dtm
		$a_01_5 = {43 68 65 63 6b 69 6e 67 20 49 6e 74 65 72 6e 65 74 20 75 73 69 6e 67 20 75 72 6c 3a 20 25 73 } //01 00  Checking Internet using url: %s
		$a_01_6 = {43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 45 00 58 00 45 00 } //00 00  Client.EXE
		$a_01_7 = {00 5d 04 00 } //00 8e 
	condition:
		any of ($a_*)
 
}