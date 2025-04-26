
rule Trojan_Win32_RacoonStealer_RPD_MTB{
	meta:
		description = "Trojan:Win32/RacoonStealer.RPD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 84 24 34 08 00 00 8b 4c 24 18 8b 54 24 14 5e 5d 89 08 89 50 04 5b 81 c4 24 08 00 00 c2 04 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}