
rule Trojan_Win64_IcedId_HB_MTB{
	meta:
		description = "Trojan:Win64/IcedId.HB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 04 0a eb af eb 9d 8b c2 48 98 66 3b c9 74 b3 99 f7 7c 24 58 3a db 74 ee 8b 4c 24 04 33 c8 3a ed 74 98 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}