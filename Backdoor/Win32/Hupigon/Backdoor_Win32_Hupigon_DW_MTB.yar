
rule Backdoor_Win32_Hupigon_DW_MTB{
	meta:
		description = "Backdoor:Win32/Hupigon.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 c2 01 da 8b 12 81 e2 ?? ?? ?? ?? 8b 59 ?? 01 c3 c1 e2 ?? 01 d3 8b 13 } //1
		$a_03_1 = {8a 18 80 c3 ?? 80 f3 ?? 80 c3 ?? 88 18 40 49 83 f9 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}