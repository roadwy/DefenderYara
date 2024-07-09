
rule Trojan_Win32_Fauppod_PQ_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c7 01 88 47 ?? 83 c2 01 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 85 c9 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}