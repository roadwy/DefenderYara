
rule PWS_Win32_Fareit_AQ_MTB{
	meta:
		description = "PWS:Win32/Fareit.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 34 01 7e [0-40] 41 [0-50] 39 d9 [0-40] 75 [0-50] 05 ?? ?? 00 00 [0-50] ff e1 } //1
		$a_03_1 = {89 c9 80 34 01 [0-40] 41 [0-50] 39 d9 [0-40] 75 [0-50] 05 ?? ?? 00 00 [0-50] ff e1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}