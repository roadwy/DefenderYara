
rule Trojan_Win32_RaccoonStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/RaccoonStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 d0 61 c6 45 d1 6b c6 45 d2 68 c6 45 d3 6a c6 45 d4 66 c6 45 d5 77 c6 45 d6 78 c6 45 d7 6d c6 45 d8 73 c6 45 d9 49 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}