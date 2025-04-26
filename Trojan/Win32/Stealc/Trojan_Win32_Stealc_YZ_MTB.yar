
rule Trojan_Win32_Stealc_YZ_MTB{
	meta:
		description = "Trojan:Win32/Stealc.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4d fc 30 0c 1f 47 3b 7d ?? 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Stealc_YZ_MTB_2{
	meta:
		description = "Trojan:Win32/Stealc.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}