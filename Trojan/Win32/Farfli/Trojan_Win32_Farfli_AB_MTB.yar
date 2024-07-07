
rule Trojan_Win32_Farfli_AB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 84 05 3c 98 f0 ff 66 0f ef c1 f3 0f 7f 84 05 3c 98 f0 ff 83 c0 10 3d c0 67 0f 00 75 e0 } //1
		$a_01_1 = {46 69 6c 65 20 63 72 65 61 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //1 File created successfully.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Farfli_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.AB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 74 24 0c 80 c2 21 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //1
		$a_01_1 = {8b 0b 8b 73 04 8b 7c 24 18 8b d1 03 f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 20 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 0f 8c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}