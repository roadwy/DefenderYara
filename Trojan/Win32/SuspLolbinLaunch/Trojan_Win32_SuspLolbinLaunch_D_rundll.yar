
rule Trojan_Win32_SuspLolbinLaunch_D_rundll{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.D!rundll,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 [0-60] 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}