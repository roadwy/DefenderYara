
rule Trojan_Win64_ZLoader_DD_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 58 a6 41 2c bc 6d d7 0d 3e be 4b 43 25 db cc 79 23 4a a4 ff e2 b2 80 00 c1 6b 75 70 18 0b 5f be } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}