
rule Ransom_Win32_Clop_H{
	meta:
		description = "Ransom:Win32/Clop.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 00 5f 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 52 00 54 00 46 00 } //1 !_READ_ME.RTF
		$a_01_1 = {2e 00 43 00 5f 00 49 00 5f 00 30 00 50 00 } //1 .C_I_0P
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}