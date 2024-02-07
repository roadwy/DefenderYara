
rule Trojan_Win32_Dialer_A_MTB{
	meta:
		description = "Trojan:Win32/Dialer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c2 03 c0 8d 44 c1 90 01 01 8b 1e 89 18 89 06 42 83 fa 90 00 } //02 00 
		$a_01_1 = {74 68 69 6e 64 69 61 6c 65 72 } //00 00  thindialer
	condition:
		any of ($a_*)
 
}