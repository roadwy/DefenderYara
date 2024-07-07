
rule Trojan_Win32_Fauppod_PR_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 01 01 90 90 90 90 8a 06 46 90 90 51 83 c4 04 32 02 88 07 47 89 c0 42 83 ec 04 c7 04 24 90 01 04 83 c4 04 49 68 90 01 04 83 c4 04 85 c9 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}