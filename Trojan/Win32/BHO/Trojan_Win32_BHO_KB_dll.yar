
rule Trojan_Win32_BHO_KB_dll{
	meta:
		description = "Trojan:Win32/BHO.KB!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 70 75 6d 79 6e 65 77 3d } //1 ppumynew=
		$a_01_1 = {25 73 74 62 63 66 67 6e 6c 2e 69 6e 69 } //1 %stbcfgnl.ini
		$a_01_2 = {25 73 70 70 66 69 6c 65 63 6e 66 67 2e 69 6e 69 } //1 %sppfilecnfg.ini
		$a_01_3 = {21 2a 26 2a 6e 6f 6e 65 2d 76 61 6c 75 65 2a 26 21 2a } //1 !*&*none-value*&!*
		$a_03_4 = {2f 74 6e 73 2f 74 62 74 6e 73 30 34 30 31 2e 68 74 6d 90 0a 30 00 68 74 74 70 3a 2f 2f 74 62 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}