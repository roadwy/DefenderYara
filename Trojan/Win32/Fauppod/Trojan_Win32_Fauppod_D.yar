
rule Trojan_Win32_Fauppod_D{
	meta:
		description = "Trojan:Win32/Fauppod.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 64 50 66 78 4d 61 51 2e 70 64 62 00 } //1
		$a_03_1 = {66 c7 00 4d 5a 90 02 03 c7 90 01 01 3c c0 00 00 00 c7 90 01 01 c0 00 00 00 50 45 90 00 } //1
		$a_03_2 = {e8 18 00 00 00 90 01 16 ff d0 90 01 1e e2 c8 90 00 } //1
		$a_03_3 = {8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 90 02 02 8a 24 0a 28 c4 88 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}