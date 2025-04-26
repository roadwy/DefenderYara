
rule Trojan_Win32_Vundo_gen_Q{
	meta:
		description = "Trojan:Win32/Vundo.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 7a 73 05 90 09 03 00 (c7 04 24|?? ?? 68 )} //1
		$a_03_1 = {80 93 a5 5f 90 09 03 00 (c7 04 24|?? ?? 68 )} //1
		$a_03_2 = {f4 57 cf 2b 90 09 03 00 (c7 04 24|?? ?? 68 )} //1
		$a_03_3 = {92 f5 ee 39 90 09 03 00 (c7 04 24|?? ?? 68 )} //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}