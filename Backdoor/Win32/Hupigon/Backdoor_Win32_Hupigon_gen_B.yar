
rule Backdoor_Win32_Hupigon_gen_B{
	meta:
		description = "Backdoor:Win32/Hupigon.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4a 00 8b 00 8b 15 90 01 02 49 00 e8 90 01 02 fb ff a1 90 01 02 4a 00 8b 00 e8 90 01 02 fb ff c3 8b c0 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 90 01 02 4a 00 c7 40 04 07 00 00 00 eb 51 90 09 03 00 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}