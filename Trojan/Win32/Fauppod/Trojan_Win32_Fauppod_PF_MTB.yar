
rule Trojan_Win32_Fauppod_PF_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 [0-06] 83 c6 01 8a 46 ?? 89 c0 32 02 88 07 47 56 83 c4 04 83 c2 01 49 51 83 c4 04 90 90 85 c9 75 ?? 61 c9 c2 10 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}