
rule Trojan_Win32_Fauppod_PK_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 ?? 90 90 90 90 ac 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 47 89 c0 83 c2 01 57 83 c4 04 83 e9 01 56 83 c4 04 85 c9 75 ?? 61 c9 c2 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}