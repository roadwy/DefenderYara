
rule Trojan_Win64_SparkRat_RTS_MTB{
	meta:
		description = "Trojan:Win64/SparkRat.RTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b9 42 57 b3 bf 65 9c 7e 6a 48 ba a0 e3 b6 1f e5 d2 3e 1e 48 03 14 08 31 c9 48 ff e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}