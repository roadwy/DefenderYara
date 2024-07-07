
rule Trojan_Win32_NekoStealer_RPL_MTB{
	meta:
		description = "Trojan:Win32/NekoStealer.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f7 8a 04 2a c0 e0 05 30 04 19 41 3b ce 72 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}