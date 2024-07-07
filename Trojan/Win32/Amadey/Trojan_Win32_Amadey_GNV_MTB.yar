
rule Trojan_Win32_Amadey_GNV_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //1 \Amadey\Release\Amadey.pdb
		$a_80_1 = {78 6d 73 63 6f 72 65 65 2e 64 6c 6c } //xmscoree.dll  1
		$a_01_2 = {42 67 77 63 4e 6c 45 44 32 4f 31 36 } //1 BgwcNlED2O16
		$a_01_3 = {36 6c 52 6b 33 4a 41 78 50 72 46 36 } //1 6lRk3JAxPrF6
		$a_01_4 = {77 4f 6b 6a 50 56 33 79 4f 4b 58 3d } //1 wOkjPV3yOKX=
		$a_01_5 = {32 34 35 38 34 39 30 36 37 35 38 } //1 24584906758
		$a_01_6 = {45 56 52 6b 65 5a 51 41 32 79 52 69 } //1 EVRkeZQA2yRi
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}