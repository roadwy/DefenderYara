
rule Ransom_Win32_Cerber_I{
	meta:
		description = "Ransom:Win32/Cerber.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 01 68 40 e8 7d 2c ?? e8 } //1
		$a_01_1 = {0f 05 48 81 c4 00 01 00 00 e8 00 00 00 00 c7 44 24 04 23 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}