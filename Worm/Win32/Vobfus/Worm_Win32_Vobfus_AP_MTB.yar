
rule Worm_Win32_Vobfus_AP_MTB{
	meta:
		description = "Worm:Win32/Vobfus.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 ca 11 43 00 30 12 43 00 80 12 43 00 92 12 43 00 e2 } //2
		$a_01_1 = {43 00 ee 2f 43 00 38 30 43 00 82 30 43 00 cc 30 43 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}