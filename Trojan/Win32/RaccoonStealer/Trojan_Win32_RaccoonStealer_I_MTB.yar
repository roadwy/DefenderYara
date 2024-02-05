
rule Trojan_Win32_RaccoonStealer_I_MTB{
	meta:
		description = "Trojan:Win32/RaccoonStealer.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 36 23 01 00 01 45 90 02 08 03 90 01 02 8b 90 01 02 03 90 01 02 8a 90 01 01 88 90 00 } //01 00 
		$a_02_1 = {55 8b ec 83 90 02 15 c6 05 90 01 04 6f c6 05 90 01 04 69 c6 05 90 01 04 56 c6 05 90 01 04 7e c6 05 90 01 04 7e c6 05 90 01 04 6c 90 02 10 c7 45 90 01 04 00 c6 05 90 01 04 65 c6 05 90 01 04 50 c6 05 90 01 04 00 c6 05 90 01 04 7c c6 05 90 01 04 63 c6 05 90 01 04 61 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 75 90 01 07 83 e8 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}