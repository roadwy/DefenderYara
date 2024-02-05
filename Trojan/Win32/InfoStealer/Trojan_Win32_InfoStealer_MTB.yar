
rule Trojan_Win32_InfoStealer_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 34 07 0f be 1e 81 c3 90 01 04 e8 90 01 04 fe cb 32 c3 47 3b 7c 24 90 01 01 88 06 90 13 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}