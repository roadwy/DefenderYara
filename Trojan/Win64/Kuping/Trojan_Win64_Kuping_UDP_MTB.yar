
rule Trojan_Win64_Kuping_UDP_MTB{
	meta:
		description = "Trojan:Win64/Kuping.UDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 83 c1 20 48 89 c8 66 0f 1f 44 00 00 48 8b 00 48 39 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}