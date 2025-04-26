
rule Trojan_Win32_Fauppod_PO_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 [0-06] 8a 06 83 c6 01 51 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 47 90 90 83 c2 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 56 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 85 c9 75 ?? 61 c9 c2 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}