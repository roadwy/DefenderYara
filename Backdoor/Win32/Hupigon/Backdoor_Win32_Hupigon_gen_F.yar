
rule Backdoor_Win32_Hupigon_gen_F{
	meta:
		description = "Backdoor:Win32/Hupigon.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a 00 8b 00 8b 15 ?? ?? 49 00 e8 ?? ?? fb ff a1 ?? ?? 4a 00 8b 00 e8 ?? ?? fb ff c3 8b c0 55 8b 45 08 8b ec 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 4a 00 c7 40 04 07 00 00 00 eb 51 90 09 03 00 a1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}