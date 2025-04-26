
rule Trojan_Win32_Fauppod_PN_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 [0-06] 83 c6 01 8a 46 ?? 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 32 02 aa 52 83 c4 04 89 c0 83 c2 01 68 ?? ?? ?? ?? 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9 75 ?? 61 c9 c2 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}