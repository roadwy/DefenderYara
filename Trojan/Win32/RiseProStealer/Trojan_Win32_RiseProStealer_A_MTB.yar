
rule Trojan_Win32_RiseProStealer_A_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 8b 4d 90 01 01 8d 34 13 81 c3 90 01 04 03 45 90 01 01 33 c6 33 c8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}