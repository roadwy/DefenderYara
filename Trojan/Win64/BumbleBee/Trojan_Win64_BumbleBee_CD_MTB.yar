
rule Trojan_Win64_BumbleBee_CD_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.CD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8b 04 01 49 83 c1 04 8b 86 38 01 00 00 44 0f af 46 54 0f af c1 41 8b d0 89 86 38 01 00 00 8b 86 d8 00 00 00 35 f7 bf 37 5b c1 ea 10 29 86 00 01 00 00 48 63 4e 74 48 8b 86 90 00 00 00 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}