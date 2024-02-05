
rule Trojan_Win32_WinDealer_LAX_MTB{
	meta:
		description = "Trojan:Win32/WinDealer.LAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 f3 8a 44 14 90 01 01 8a 14 29 32 d0 88 14 29 41 3b ce 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}