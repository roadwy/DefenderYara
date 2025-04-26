
rule Trojan_Win64_BumbleBee_FOR_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.FOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 83 88 00 00 00 45 8b 04 01 49 83 c1 04 48 8b 05 8a d3 03 00 8b 88 c0 00 00 00 81 e9 f8 c1 15 00 01 4b 5c 48 63 4b 70 44 0f af 43 6c 48 8b 83 90 00 00 00 41 8b d0 c1 ea 08 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}