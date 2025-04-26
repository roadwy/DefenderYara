
rule Trojan_Win64_CryptInject_BK_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 53 48 81 ec 10 02 00 00 65 48 8b 04 25 60 00 00 00 48 8b 58 18 48 83 c3 10 66 0f 1f 44 00 00 48 8b 1b 48 8b 53 60 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}