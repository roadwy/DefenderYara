
rule Worm_Win32_Taterf_gen_B{
	meta:
		description = "Worm:Win32/Taterf.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 6e 64 6c 6c 2e 64 6c 6c 00 5a 74 47 61 6d 65 5f 49 4e 00 5a 74 47 61 6d 65 5f 4f 55 54 00 00 00 00 00 08 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}