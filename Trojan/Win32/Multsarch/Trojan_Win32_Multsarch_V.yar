
rule Trojan_Win32_Multsarch_V{
	meta:
		description = "Trojan:Win32/Multsarch.V,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 3f 61 3d 72 61 74 65 73 26 6e 75 6d 3d 00 } //1
		$a_03_1 = {66 c7 43 10 0c 00 33 d2 8d 45 f0 89 55 fc ba 90 01 04 ff 43 1c 66 c7 43 10 18 00 66 c7 43 10 24 00 e8 90 01 04 ff 43 1c 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}