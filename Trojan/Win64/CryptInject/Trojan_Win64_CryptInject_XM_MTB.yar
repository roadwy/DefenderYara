
rule Trojan_Win64_CryptInject_XM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.XM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 49 03 dc 83 e0 90 01 01 8a 44 05 90 01 01 30 02 49 03 d4 4d 2b f4 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}