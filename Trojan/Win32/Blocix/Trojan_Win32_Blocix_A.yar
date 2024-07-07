
rule Trojan_Win32_Blocix_A{
	meta:
		description = "Trojan:Win32/Blocix.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 77 20 35 30 30 30 20 3e 6e 75 6c 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 } //1
		$a_03_1 = {8b 45 0c 85 c0 75 0c 6a 3f 68 90 01 04 e9 90 01 02 00 00 83 f8 01 75 09 6a 3f 68 90 01 04 eb 90 01 01 83 f8 02 75 90 01 01 6a 3f 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}