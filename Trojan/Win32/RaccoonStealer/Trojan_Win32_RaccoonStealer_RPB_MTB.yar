
rule Trojan_Win32_RaccoonStealer_RPB_MTB{
	meta:
		description = "Trojan:Win32/RaccoonStealer.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 24 00 00 00 00 a1 90 01 04 01 04 24 b8 d6 38 00 00 01 04 24 8b 0c 24 8b 84 24 90 90 00 00 00 8a 14 01 8b 0d 90 01 04 88 14 01 81 c4 8c 00 00 00 c2 04 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}