
rule Trojan_Win32_RiseProStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 0d ?? 50 e8 [0-04] 88 44 0d ?? 41 83 f9 ?? 72 ?? 8d 45 ?? 50 56 ff ?? 5f a3 [0-04] 5e 8b e5 5d c3 [0-10] 55 8b ec 8a 45 08 34 33 5d c2 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}