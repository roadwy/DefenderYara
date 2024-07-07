
rule Trojan_Win32_Maskload_A{
	meta:
		description = "Trojan:Win32/Maskload.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 01 6a 00 c7 05 90 01 04 4c 6f 61 64 c7 05 90 01 04 65 72 00 00 ff 15 90 01 04 8b e8 85 ed 90 00 } //1
		$a_03_1 = {8b 10 83 c0 04 81 f2 4b 53 41 4d 89 11 83 c1 04 3d 90 01 04 7c 90 00 } //1
		$a_03_2 = {8a 14 08 80 f2 90 01 01 88 14 08 40 83 f8 0c 7c f1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}