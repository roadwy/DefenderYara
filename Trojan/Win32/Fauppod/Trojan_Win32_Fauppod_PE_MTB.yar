
rule Trojan_Win32_Fauppod_PE_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 [0-06] 8a 06 46 32 02 83 c7 01 88 47 [0-04] 83 c2 01 53 83 c4 04 89 c0 83 e9 01 68 [0-04] 83 c4 04 89 c0 85 c9 75 ?? 61 c9 c2 10 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}