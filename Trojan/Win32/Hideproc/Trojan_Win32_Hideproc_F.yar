
rule Trojan_Win32_Hideproc_F{
	meta:
		description = "Trojan:Win32/Hideproc.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {57 89 c7 88 cd 89 c8 c1 e0 10 66 89 c8 89 d1 c1 f9 02 78 09 f3 ab } //1
		$a_11_1 = {74 48 69 64 65 46 69 6c 65 4d 61 70 70 69 6e 67 01 } //1
		$a_6e_2 = {68 } //8704 h
	condition:
		((#a_00_0  & 1)*1+(#a_11_1  & 1)*1+(#a_6e_2  & 1)*8704) >=3
 
}