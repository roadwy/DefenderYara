
rule Trojan_Win32_MasqProcessLaunchLolbins_D_sync{
	meta:
		description = "Trojan:Win32/MasqProcessLaunchLolbins.D!sync,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 61 00 73 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}