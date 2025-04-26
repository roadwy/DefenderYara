
rule PWS_Win32_VidarStealer_MR_MTB{
	meta:
		description = "PWS:Win32/VidarStealer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 39 81 [0-05] 90 18 47 3b fb 90 18 81 fb [0-04] 90 18 e8 [0-04] 8b 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}