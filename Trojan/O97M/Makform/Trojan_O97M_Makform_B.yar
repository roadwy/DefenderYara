
rule Trojan_O97M_Makform_B{
	meta:
		description = "Trojan:O97M/Makform.B,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 74 6f 66 69 6c 65 20 22 72 66 6d 2e 65 22 20 26 20 22 78 65 22 2c 20 32 } //2 savetofile "rfm.e" & "xe", 2
		$a_00_1 = {55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 35 5f 43 6c 69 63 6b } //1 UserForm1.Label5_Click
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1) >=2
 
}