
rule Trojan_Win64_Latrodectus_ADTZ_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.ADTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b d7 48 8b cf 48 2b d7 8a 04 0a 45 03 c4 88 01 49 63 c0 49 03 cc 49 3b c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}