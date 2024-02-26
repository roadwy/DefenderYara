
rule Trojan_Win32_ArkeiStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 1e 46 3b f7 7c e8 5d 5e 83 ff 2d 75 14 } //00 00 
	condition:
		any of ($a_*)
 
}