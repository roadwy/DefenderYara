
rule Trojan_Win32_Small_EO{
	meta:
		description = "Trojan:Win32/Small.EO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 6c 45 78 65 } //1 hlExe
		$a_01_1 = {68 53 68 65 6c } //1 hShel
		$a_01_2 = {50 58 68 65 72 50 72 } //2 PXherPr
		$a_01_3 = {50 58 68 62 75 67 67 } //2 PXhbugg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}