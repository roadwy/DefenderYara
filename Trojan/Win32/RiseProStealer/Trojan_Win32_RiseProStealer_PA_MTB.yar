
rule Trojan_Win32_RiseProStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 0d 90 01 01 50 e8 90 02 04 88 44 0d 90 01 01 41 83 f9 90 01 01 72 90 01 01 8d 45 90 01 01 50 56 ff 90 01 01 5f a3 90 02 04 5e 8b e5 5d c3 90 02 10 55 8b ec 8a 45 08 34 33 5d c2 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}