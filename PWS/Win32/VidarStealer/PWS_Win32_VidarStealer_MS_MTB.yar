
rule PWS_Win32_VidarStealer_MS_MTB{
	meta:
		description = "PWS:Win32/VidarStealer.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 31 81 fb 90 01 04 90 18 46 3b f3 90 18 81 fb 90 01 04 90 18 e8 90 01 04 8b 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}