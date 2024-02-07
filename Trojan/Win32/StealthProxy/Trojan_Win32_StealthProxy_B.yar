
rule Trojan_Win32_StealthProxy_B{
	meta:
		description = "Trojan:Win32/StealthProxy.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 77 75 70 64 74 65 30 30 32 2e 63 6f 6d } //01 00  \wupdte002.com
		$a_01_1 = {76 61 6d 6f 71 76 61 6d 6f } //02 00  vamoqvamo
		$a_01_2 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b } //03 00  user_pref("network
		$a_01_3 = {8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 3c } //00 00 
	condition:
		any of ($a_*)
 
}