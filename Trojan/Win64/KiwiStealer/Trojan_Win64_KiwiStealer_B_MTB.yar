
rule Trojan_Win64_KiwiStealer_B_MTB{
	meta:
		description = "Trojan:Win64/KiwiStealer.B!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 6b c6 28 c7 44 24 3c 00 00 00 00 48 01 e8 44 8b 50 10 8b 50 0c 8b 40 24 4c 29 e2 4c 89 54 24 50 41 89 c1 48 01 d1 41 89 c0 4c 89 d2 41 c1 e9 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}