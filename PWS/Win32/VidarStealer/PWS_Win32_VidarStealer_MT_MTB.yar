
rule PWS_Win32_VidarStealer_MT_MTB{
	meta:
		description = "PWS:Win32/VidarStealer.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 31 83 fb 90 01 01 90 18 46 3b f3 90 18 81 fb 90 02 04 90 18 e8 90 02 04 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}