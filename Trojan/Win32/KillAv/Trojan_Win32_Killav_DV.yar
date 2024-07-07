
rule Trojan_Win32_Killav_DV{
	meta:
		description = "Trojan:Win32/Killav.DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 e8 83 c2 01 89 55 e8 90 02 10 eb 90 00 } //1
		$a_03_1 = {00 61 6e 74 69 5f 61 76 90 01 01 2e 64 6c 6c 00 90 00 } //1
		$a_03_2 = {41 70 70 44 61 74 61 00 52 6f 61 6d 69 6e 67 00 4d 69 63 72 6f 73 6f 66 74 90 02 05 57 69 6e 64 6f 77 73 00 25 73 5c 25 73 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}