
rule PWS_Win32_Daceluw_A{
	meta:
		description = "PWS:Win32/Daceluw.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 5d d6 88 5d da 88 5d de c7 45 cc 68 74 74 70 c7 45 d0 3a 2f 2f } //1
		$a_01_1 = {c7 45 dc 25 73 2d 25 88 5d e1 66 c7 45 e2 58 25 88 5d e5 66 c7 45 e6 58 25 88 5d e9 66 c7 45 ea 58 25 88 5d ed 66 c7 45 ee 58 25 88 5d f1 66 c7 45 f2 58 25 88 5d f5 66 c7 45 f6 58 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}