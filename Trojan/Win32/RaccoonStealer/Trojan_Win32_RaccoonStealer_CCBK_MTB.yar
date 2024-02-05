
rule Trojan_Win32_RaccoonStealer_CCBK_MTB{
	meta:
		description = "Trojan:Win32/RaccoonStealer.CCBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 02 8d 52 90 01 01 03 c7 89 04 8b 41 3b ce 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}