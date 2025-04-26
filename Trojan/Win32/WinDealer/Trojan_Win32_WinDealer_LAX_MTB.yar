
rule Trojan_Win32_WinDealer_LAX_MTB{
	meta:
		description = "Trojan:Win32/WinDealer.LAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 f3 8a 44 14 ?? 8a 14 29 32 d0 88 14 29 41 3b ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}