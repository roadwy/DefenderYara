
rule Trojan_Win32_Stealer_MS_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {be 64 00 00 00 8b c1 99 f7 fe 8a 90 02 03 30 04 90 01 01 41 81 f9 90 01 04 7c eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}