
rule Trojan_Win64_SeStealer_A_MTB{
	meta:
		description = "Trojan:Win64/SeStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 12 48 8b c5 49 03 d3 0f b6 0a 84 c9 90 01 02 48 6b c0 90 01 01 48 0f be c9 48 8d 52 01 48 03 c1 0f b6 0a 84 c9 90 01 02 48 3b c3 90 01 02 41 ff c1 49 83 c2 90 01 01 45 3b c8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}