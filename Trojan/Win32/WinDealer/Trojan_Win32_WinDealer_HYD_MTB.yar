
rule Trojan_Win32_WinDealer_HYD_MTB{
	meta:
		description = "Trojan:Win32/WinDealer.HYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 bb 90 01 04 f7 f3 8a 1c 31 8b 44 24 90 01 01 8a 54 3a 90 01 01 32 da 88 1c 31 41 3b c8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}