
rule Trojan_Win32_Conhook_D{
	meta:
		description = "Trojan:Win32/Conhook.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 75 70 65 72 6a 75 61 6e } //01 00  superjuan
		$a_00_1 = {4a 75 61 6e 5f 54 72 61 63 6b 69 6e 67 5f 4d 75 74 65 78 } //01 00  Juan_Tracking_Mutex
		$a_00_2 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //01 00  Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_02_3 = {2f 72 65 64 69 72 65 63 74 2f 90 02 03 2e 70 68 70 90 00 } //01 00 
		$a_02_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 90 03 04 07 4a 75 61 6e 4d 53 20 4a 75 61 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Conhook_D_2{
	meta:
		description = "Trojan:Win32/Conhook.D,SIGNATURE_TYPE_PEHSTR,29 00 28 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 65 61 72 63 68 74 65 72 6d 3d 00 61 6c 6c 79 6f 75 72 73 65 61 72 63 68 2e 63 6f 6d } //0a 00 
		$a_01_1 = {74 65 72 6d 73 3d 00 00 73 65 78 2e 63 6f 6d } //0a 00 
		$a_01_2 = {73 3d 00 00 36 36 2e 32 32 30 2e 31 37 2e 31 35 37 } //0a 00 
		$a_01_3 = {3f 63 6d 70 3d 73 75 70 65 72 6a 75 61 6e 26 75 69 64 3d 25 73 26 67 75 69 64 3d 25 73 } //01 00  ?cmp=superjuan&uid=%s&guid=%s
		$a_01_4 = {44 75 6e 63 61 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 64 6f 5f 77 6f 72 6b } //01 00  畄据湡搮汬䐀汬慃啮汮慯乤睯䐀汬敇䍴慬獳扏敪瑣搀彯潷歲
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4a 75 61 6e } //01 00  Software\Microsoft\Juan
		$a_01_6 = {68 74 74 70 3a 2f 2f 36 35 2e 32 34 33 2e 31 30 33 2e 35 38 2f 74 72 61 66 63 2d 32 2f 72 66 65 2e 70 68 70 } //00 00  http://65.243.103.58/trafc-2/rfe.php
	condition:
		any of ($a_*)
 
}