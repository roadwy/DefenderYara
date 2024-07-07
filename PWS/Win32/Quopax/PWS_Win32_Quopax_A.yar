
rule PWS_Win32_Quopax_A{
	meta:
		description = "PWS:Win32/Quopax.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 6c ee ff ff 56 ff 15 90 01 03 00 68 94 11 00 00 e8 90 01 02 00 00 83 c4 04 8b f8 8d 45 fc 6a 00 50 68 94 11 00 00 90 00 } //1
		$a_03_1 = {6a 7c 56 e8 90 01 02 00 00 6a 24 56 8b f8 e8 90 01 02 00 00 8b d8 6a 40 56 89 5d fc e8 90 01 02 00 00 6a 23 56 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}