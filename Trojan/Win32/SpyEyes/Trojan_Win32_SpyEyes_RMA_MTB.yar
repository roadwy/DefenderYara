
rule Trojan_Win32_SpyEyes_RMA_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 eb 90 01 01 8b 45 90 01 01 05 f8 00 00 00 89 45 90 01 01 8b 4d 90 01 01 51 e8 90 01 04 83 c4 04 c7 45 90 01 01 00 00 00 00 eb 90 01 01 8b 55 90 01 01 83 c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}