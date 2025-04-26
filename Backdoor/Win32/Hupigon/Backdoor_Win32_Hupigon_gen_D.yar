
rule Backdoor_Win32_Hupigon_gen_D{
	meta:
		description = "Backdoor:Win32/Hupigon.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {47 00 8b 00 8b 15 ?? ?? 46 00 e8 ?? ?? fe ff a1 ?? ?? 47 00 8b 00 e8 ?? ?? fe ff 5d c2 04 00 [0-01] a1 ?? ?? 47 00 50 6a 00 6a 00 68 ?? ?? 46 00 6a 00 6a 00 e8 ?? ?? ?? ff 8b 15 ?? ?? 47 00 89 02 c3 [0-03] 83 c4 ?? c7 04 24 90 09 03 00 a1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}