
rule Trojan_Win32_Fauppod_PD_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 [0-06] 68 ?? ?? ?? ?? 83 c4 04 8a 06 46 53 83 c4 04 32 02 88 07 47 89 c0 83 c2 01 90 90 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 85 c9 75 ?? 61 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}