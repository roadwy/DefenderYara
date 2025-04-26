
rule PWS_Win32_Tibia_AM{
	meta:
		description = "PWS:Win32/Tibia.AM,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 52 49 57 5a 44 55 48 5f 50 6c 66 75 72 76 72 69 77 5f 5a 6c 71 67 72 7a 76 5f 46 78 75 75 68 71 77 59 68 75 76 6c 72 71 5f 55 78 71 } //1 VRIWZDUH_Plfurvriw_Zlqgrzv_FxuuhqwYhuvlrq_Uxq
		$a_01_1 = {29 64 66 66 72 78 71 77 71 64 70 68 40 } //1 )dffrxqwqdph@
		$a_01_2 = {29 66 6b 64 75 64 66 77 68 75 40 } //1 )fkdudfwhu@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}