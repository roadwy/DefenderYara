
rule TrojanProxy_Win32_Bunitu_R_bit{
	meta:
		description = "TrojanProxy:Win32/Bunitu.R!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 74 6e 76 69 61 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 61 74 6e 76 69 61 } //2
		$a_03_1 = {89 4a 04 83 6a 04 90 01 01 b8 01 00 00 00 48 b9 90 01 04 41 90 00 } //1
		$a_03_2 = {fe 09 c6 41 90 01 02 fe 49 90 01 01 c6 41 90 01 02 fe 49 90 01 01 fe 09 51 e8 68 20 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanProxy_Win32_Bunitu_R_bit_2{
	meta:
		description = "TrojanProxy:Win32/Bunitu.R!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3 } //1
		$a_01_1 = {83 c0 78 83 c0 78 c1 e8 0a 56 be 3c 00 00 00 3b c6 72 10 83 e8 1e 83 e8 1e 41 3b ce 75 03 } //1
		$a_03_2 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 90 01 04 87 d1 29 10 59 90 00 } //1
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 52 75 6e 64 6c 6c 33 32 22 20 64 69 72 3d 6f 75 74 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 74 6f 63 6f 6c 3d 61 6e 79 } //1 advfirewall firewall add rule name="Rundll32" dir=out action=allow protocol=any
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}