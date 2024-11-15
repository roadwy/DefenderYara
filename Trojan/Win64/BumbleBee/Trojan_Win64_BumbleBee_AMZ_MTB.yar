
rule Trojan_Win64_BumbleBee_AMZ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 4f 40 8b 8f 8c 00 00 00 48 8b 05 f6 f8 09 00 2b 48 2c 83 f1 f8 01 8f 18 01 00 00 44 0f af 87 84 00 00 00 48 63 0d 7b f9 09 00 48 8b 05 d4 f9 09 00 41 8b d0 c1 ea 10 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}