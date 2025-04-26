
rule Trojan_Win32_Stealbit_RB_MTB{
	meta:
		description = "Trojan:Win32/Stealbit.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2f 00 78 00 c7 44 24 ?? 76 00 2e 00 [0-15] c7 44 24 ?? 2f 00 25 00 c7 44 24 ?? 64 00 2e 00 [0-15] c7 44 24 ?? 6d 00 6c 00 [0-15] c7 44 24 ?? 74 00 70 00 c7 44 24 ?? 3a 00 2f 00 c7 44 24 ?? 2f 00 78 00 c7 44 24 ?? 76 00 2e 00 [0-15] c7 44 24 ?? 2f 00 6c 00 c7 44 24 ?? 6f 00 67 00 c7 84 24 ?? 00 00 00 6f 00 2e 00 c7 84 24 ?? 00 00 00 70 00 6e 00 c7 84 24 ?? 00 00 00 67 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}