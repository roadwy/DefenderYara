
rule Trojan_Win32_MasqProcessLaunchLolbins_C_sync{
	meta:
		description = "Trojan:Win32/MasqProcessLaunchLolbins.C!sync,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 6f 00 61 00 6d 00 69 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}