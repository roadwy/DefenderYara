
rule PWS_Win32_Zuten_gen_C{
	meta:
		description = "PWS:Win32/Zuten.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 02 57 6a fc [0-20] ff d3 81 7d ?? 1c 4d 5f 23 [0-14] 6a 02 57 6a f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}