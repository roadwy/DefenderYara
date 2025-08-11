
rule Trojan_Win64_Lazy_AQ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 40 0f be 00 44 31 e8 44 69 e0 95 e9 d1 5b 44 33 64 24 54 b8 00 ad 85 3a 3d 58 15 53 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}