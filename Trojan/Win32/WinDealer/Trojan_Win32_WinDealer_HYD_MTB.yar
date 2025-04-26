
rule Trojan_Win32_WinDealer_HYD_MTB{
	meta:
		description = "Trojan:Win32/WinDealer.HYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 bb ?? ?? ?? ?? f7 f3 8a 1c 31 8b 44 24 ?? 8a 54 3a ?? 32 da 88 1c 31 41 3b c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}