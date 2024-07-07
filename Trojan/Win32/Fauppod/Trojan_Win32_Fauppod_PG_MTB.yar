
rule Trojan_Win32_Fauppod_PG_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 02 06 8a 06 83 c6 01 89 c0 32 02 68 90 01 04 83 c4 04 47 88 47 90 01 01 89 c0 90 90 83 c2 01 83 e9 01 51 83 c4 04 85 c9 75 90 01 01 61 c9 c2 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}