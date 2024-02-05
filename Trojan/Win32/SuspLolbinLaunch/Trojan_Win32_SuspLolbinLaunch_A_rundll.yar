
rule Trojan_Win32_SuspLolbinLaunch_A_rundll{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.A!rundll,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 90 02 50 5c 00 5c 00 90 00 } //01 00 
		$a_02_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 90 02 50 68 00 74 00 74 00 70 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}