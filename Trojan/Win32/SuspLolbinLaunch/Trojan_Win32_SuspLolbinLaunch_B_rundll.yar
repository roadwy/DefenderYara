
rule Trojan_Win32_SuspLolbinLaunch_B_rundll{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.B!rundll,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 90 02 40 6d 00 73 00 68 00 74 00 6d 00 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}