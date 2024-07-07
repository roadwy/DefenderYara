
rule Trojan_Win32_Fauppod_PI_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 01 01 90 90 90 90 83 ec 04 c7 04 24 90 01 04 83 c4 04 8a 06 83 c6 01 90 90 32 02 56 83 c4 04 88 07 83 c7 01 56 83 c4 04 42 83 e9 01 89 c0 85 c9 75 90 01 01 61 c9 c2 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}