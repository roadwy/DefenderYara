
rule Trojan_Win32_Zlob_gen_S{
	meta:
		description = "Trojan:Win32/Zlob.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 8d 44 24 90 01 01 68 00 00 00 80 50 ff 91 90 01 02 00 00 90 00 } //1
		$a_00_1 = {76 63 32 30 78 63 30 30 75 } //1 vc20xc00u
		$a_00_2 = {50 47 e8 89 ff ff ff 88 06 8a 07 83 c4 04 46 84 c0 75 ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}