
rule Trojan_Win32_PovertyStealer_A_MTB{
	meta:
		description = "Trojan:Win32/PovertyStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 8b c1 c1 e8 90 01 01 33 c1 69 c8 90 01 04 33 f9 3b f3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}