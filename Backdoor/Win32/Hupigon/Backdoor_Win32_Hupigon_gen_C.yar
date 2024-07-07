
rule Backdoor_Win32_Hupigon_gen_C{
	meta:
		description = "Backdoor:Win32/Hupigon.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ba 02 00 00 00 e8 8c f9 ff ff 84 c0 0f 84 90 90 01 00 00 b2 01 a1 18 98 90 01 02 e8 10 e3 ff ff 90 09 0a 00 b9 4c e9 90 01 02 b8 90 01 01 b7 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}