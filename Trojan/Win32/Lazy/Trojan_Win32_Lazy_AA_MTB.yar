
rule Trojan_Win32_Lazy_AA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 c8 83 cb ?? 0f b6 cb 01 c1 0f b7 5c 77 ?? 46 66 85 db 75 } //20
		$a_03_1 = {0f b6 44 24 05 8b 4c 24 30 8b 54 24 34 01 c8 c1 e1 ?? 01 c8 89 84 24 cc 00 00 00 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}