
rule Trojan_Win64_CryptInject_YTD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 0d 48 0f 00 00 ba 00 00 00 80 45 31 c0 31 c0 41 89 c1 c7 44 24 20 04 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 30 00 00 00 00 ff 15 d4 0f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}