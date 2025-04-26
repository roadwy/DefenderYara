
rule Ransom_Win32_Clop_I{
	meta:
		description = "Ransom:Win32/Clop.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 00 65 00 6d 00 70 00 2e 00 6f 00 63 00 78 00 } //1 temp.ocx
		$a_01_1 = {43 00 68 00 61 00 6e 00 67 00 65 00 72 00 57 00 69 00 66 00 69 00 } //1 ChangerWifi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}