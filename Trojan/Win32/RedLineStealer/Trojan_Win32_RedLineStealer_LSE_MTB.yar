
rule Trojan_Win32_RedLineStealer_LSE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.LSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 81 e1 90 01 04 79 90 01 01 49 81 c9 90 01 04 41 8a 89 90 01 04 88 4d fb 0f b6 45 fb 8b 0d 90 01 04 03 4d e0 0f be 11 33 d0 a1 90 01 04 03 45 e0 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}