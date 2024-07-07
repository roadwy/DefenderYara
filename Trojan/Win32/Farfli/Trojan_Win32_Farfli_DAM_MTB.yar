
rule Trojan_Win32_Farfli_DAM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 32 c2 02 c2 88 01 41 83 ee 01 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Farfli_DAM_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 c2 66 80 f2 fe 88 14 01 41 3b ce 7c } //2
		$a_03_1 = {56 57 6a 04 68 00 10 00 00 55 6a 00 ff 15 90 02 04 8b f8 8b cb 89 7c 24 1c e8 90 00 } //2
		$a_01_2 = {5b 45 78 65 63 75 74 65 5d } //1 [Execute]
		$a_01_3 = {5b 42 61 63 6b 73 70 61 63 65 5d } //1 [Backspace]
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}