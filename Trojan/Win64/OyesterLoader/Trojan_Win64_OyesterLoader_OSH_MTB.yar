
rule Trojan_Win64_OyesterLoader_OSH_MTB{
	meta:
		description = "Trojan:Win64/OyesterLoader.OSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 59 10 48 8b d3 48 8b 4a 60 45 8b ce 48 8b c1 66 44 39 31 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}