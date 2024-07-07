
rule PWS_Win32_Daurso_gen_A{
	meta:
		description = "PWS:Win32/Daurso.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d 38 4a 00 00 75 ed 5a 5e 5b c3 90 09 07 00 e8 90 01 04 33 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}