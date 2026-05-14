
rule Trojan_Win64_DustyHammock_GVB_MTB{
	meta:
		description = "Trojan:Win64/DustyHammock.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 dc a8 01 0f 85 4d 0c 00 00 32 55 e3 8b 4d d8 8b 45 bc 46 88 14 08 8b 45 d4 41 eb b3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}