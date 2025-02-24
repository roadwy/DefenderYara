
rule Trojan_Win64_CryptInject_EEP_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.EEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c7 49 c7 c3 14 00 00 00 48 31 c0 48 31 c9 66 4d 0f 7e e9 49 81 c1 ?? ?? ?? ?? 48 31 d2 49 f7 f3 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 ff 2d 00 00 76 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}