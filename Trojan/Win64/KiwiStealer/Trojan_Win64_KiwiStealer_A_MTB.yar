
rule Trojan_Win64_KiwiStealer_A_MTB{
	meta:
		description = "Trojan:Win64/KiwiStealer.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b c8 49 2b c8 49 8b d0 48 2b d0 49 3b c0 48 0f 43 d1 69 05 8e 35 02 00 80 51 01 00 48 63 c8 48 69 c1 80 96 98 00 48 3b d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}