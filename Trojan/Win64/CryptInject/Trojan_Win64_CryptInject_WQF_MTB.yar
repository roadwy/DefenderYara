
rule Trojan_Win64_CryptInject_WQF_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.WQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 bf 00 30 00 00 41 bc 00 d0 1b 00 41 b9 04 00 00 00 33 c9 45 8b c7 41 8b d4 48 89 45 7f ff d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}